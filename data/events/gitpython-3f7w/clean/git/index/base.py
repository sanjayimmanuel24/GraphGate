"""Module containing :class:`IndexFile`, an Index implementation facilitating all kinds
of index manipulations such as querying and merging."""

import contextlib
import datetime
import glob
from io import BytesIO
import os
import os.path as osp
from stat import S_ISLNK
import subprocess
import sys
import tempfile

from gitdb.base import IStream
from gitdb.db import MemoryDB

from git.compat import defenc, force_bytes
from git.cmd import Git
import git.diff as git_diff
from git.exc import CheckoutError, GitCommandError, GitError, InvalidGitRepositoryError
from git.objects import Blob, Commit, Object, Submodule, Tree
from git.objects.util import Serializable
from git.util import (
    Actor,
    LazyMixin,
    LockedFD,
    join_path_native,
    file_contents_ro,
    to_native_path_linux,
    unbare_repo,
    to_bin_sha,
)

from .fun import (
    S_IFGITLINK,
    aggressive_tree_merge,
    entry_key,
    read_cache,
    run_commit_hook,
    stat_mode_to_index_mode,
    write_cache,
    write_tree_from_cache,
)
from .typ import BaseIndexEntry, IndexEntry, StageType
from .util import TemporaryFileSwap, post_clear_cache, default_index, git_working_dir

from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Generator,
    IO,
    Iterable,
    Iterator,
    List,
    NoReturn,
    Sequence,
    TYPE_CHECKING,
    Tuple,
    Union,
)

from git.types import Literal, PathLike

if TYPE_CHECKING:
    from subprocess import Popen

    from git.refs.reference import Reference
    from git.repo import Repo


class IndexFile(LazyMixin, git_diff.Diffable, Serializable):
    """An Index that can be manipulated using a native implementation in order to save
    git command function calls wherever possible.

    This provides custom merging facilities allowing to merge without actually changing
    your index or your working tree. This way you can perform your own test merges based
    on the index only without having to deal with the working copy. This is useful in
    case of partial working trees.

    Entries:

        The index contains an entries dict whose keys are tuples of type
        :class:`~git.index.typ.IndexEntry` to facilitate access.

        You may read the entries dict or manipulate it using IndexEntry instance, i.e.::

            index.entries[index.entry_key(index_entry_instance)] = index_entry_instance

    Make sure you use :meth:`index.write() <write>` once you are done manipulating the
    index directly before operating on it using the git command.
    """

    unsafe_git_checkout_index_options = ["--prefix"]

    __slots__ = ("repo", "version", "entries", "_extension_data", "_file_path")

    _VERSION = 2

    S_IFGITLINK = S_IFGITLINK

    @default_index
    def checkout(
        self,
        paths: Union[None, Iterable[PathLike]] = None,
        force: bool = False,
        fprogress: Callable = lambda *args: None,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> Union[None, Iterator[PathLike], Sequence[PathLike]]:
        """Check out the given paths or all files from the version known to the index
        into the working tree.

        :note:
            Be sure you have written pending changes using the :meth:`write` method in
            case you have altered the entries dictionary directly.

        :param paths:
            If ``None``, all paths in the index will be checked out.
            Otherwise an iterable of relative or absolute paths or a single path
            pointing to files or directories in the index is expected.

        :param force:
            If ``True``, existing files will be overwritten even if they contain local
            modifications.
            If ``False``, these will trigger a :exc:`~git.exc.CheckoutError`.

        :param fprogress:
            See :meth:`IndexFile.add` for signature and explanation.

            The provided progress information will contain ``None`` as path and item if
            no explicit paths are given. Otherwise progress information will be send
            prior and after a file has been checked out.

        :param allow_unsafe_options:
            Allow unsafe options, such as ``--prefix``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-checkout-index(1)`.

        :return:
            Iterable yielding paths to files which have been checked out and are
            guaranteed to match the version stored in the index.

        :raise git.exc.CheckoutError:
            * If at least one file failed to be checked out. This is a summary, hence it
              will checkout as many files as it can anyway.
            * If one of files or directories do not exist in the index (as opposed to
              the original git command, which ignores them).

        :raise git.exc.GitCommandError:
            If error lines could not be parsed - this truly is an exceptional state.

        :note:
            The checkout is limited to checking out the files in the index. Files which
            are not in the index anymore and exist in the working tree will not be
            deleted. This behaviour is fundamentally different to ``head.checkout``,
            i.e. if you want :manpage:`git-checkout(1)`-like behaviour, use
            ``head.checkout`` instead of ``index.checkout``.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_checkout_index_options,
            )

        args = ["--index"]
        if force:
            args.append("--force")

        failed_files = []
        failed_reasons = []
        unknown_lines = []

        def handle_stderr(proc: "Popen[bytes]", iter_checked_out_files: Iterable[PathLike]) -> None:
            stderr_IO = proc.stderr
            if not stderr_IO:
                return  # Return early if stderr empty.

            stderr_bytes = stderr_IO.read()
            # line contents:
            stderr = stderr_bytes.decode(defenc)
            # git-checkout-index: this already exists
            endings = (
                " already exists",
                " is not in the cache",
                " does not exist at stage",
                " is unmerged",
            )
            for line in stderr.splitlines():
                if not line.startswith("git checkout-index: ") and not line.startswith("git-checkout-index: "):
                    is_a_dir = " is a directory"
                    unlink_issue = "unable to unlink old '"
                    already_exists_issue = " already exists, no checkout"  # created by entry.c:checkout_entry(...)
                    if line.endswith(is_a_dir):
                        failed_files.append(line[: -len(is_a_dir)])
                        failed_reasons.append(is_a_dir)
                    elif line.startswith(unlink_issue):
                        failed_files.append(line[len(unlink_issue) : line.rfind("'")])
                        failed_reasons.append(unlink_issue)
                    elif line.endswith(already_exists_issue):
                        failed_files.append(line[: -len(already_exists_issue)])
                        failed_reasons.append(already_exists_issue)
                    else:
                        unknown_lines.append(line)
                    continue
                # END special lines parsing

                for e in endings:
                    if line.endswith(e):
                        failed_files.append(line[20 : -len(e)])
                        failed_reasons.append(e)
                        break
                    # END if ending matches
                # END for each possible ending
            # END for each line
            if unknown_lines:
                raise GitCommandError(("git-checkout-index",), 128, stderr)
            if failed_files:
                valid_files = list(set(iter_checked_out_files) - set(failed_files))
                raise CheckoutError(
                    "Some files could not be checked out from the index due to local modifications",
                    failed_files,
                    valid_files,
                    failed_reasons,
                )

        # END stderr handler

        if paths is None:
            args.append("--all")
            kwargs["as_process"] = 1
            fprogress(None, False, None)
            proc = self.repo.git.checkout_index(*args, **kwargs)
            proc.wait()
            fprogress(None, True, None)
            rval_iter = (e.path for e in self.entries.values())
            handle_stderr(proc, rval_iter)
            return rval_iter
        else:
            if isinstance(paths, str):
                paths = [paths]

            # Make sure we have our entries loaded before we start checkout_index, which
            # will hold a lock on it. We try to get the lock as well during our entries
            # initialization.
            self.entries  # noqa: B018

            args.append("--stdin")
            kwargs["as_process"] = True
            kwargs["istream"] = subprocess.PIPE
            proc = self.repo.git.checkout_index(args, **kwargs)

            # FIXME: Reading from GIL!
            def make_exc() -> GitCommandError:
                return GitCommandError(("git-checkout-index", *args), 128, proc.stderr.read())

            checked_out_files: List[PathLike] = []

            for path in paths:
                co_path = to_native_path_linux(self._to_relative_path(path))
                # If the item is not in the index, it could be a directory.
                path_is_directory = False

                try:
                    self.entries[(co_path, 0)]
                except KeyError:
                    folder = co_path
                    if not folder.endswith("/"):
                        folder += "/"
                    for entry in self.entries.values():
                        if os.fspath(entry.path).startswith(folder):
                            p = entry.path
                            self._write_path_to_stdin(proc, p, p, make_exc, fprogress, read_from_stdout=False)
                            checked_out_files.append(p)
                            path_is_directory = True
                        # END if entry is in directory
                    # END for each entry
                # END path exception handlnig

                if not path_is_directory:
                    self._write_path_to_stdin(proc, co_path, path, make_exc, fprogress, read_from_stdout=False)
                    checked_out_files.append(co_path)
                # END path is a file
            # END for each path
            try:
                self._flush_stdin_and_wait(proc, ignore_stdout=True)
            except GitCommandError:
                # Without parsing stdout we don't know what failed.
                raise CheckoutError(  # noqa: B904
                    "Some files could not be checked out from the index, probably because they didn't exist.",
                    failed_files,
                    [],
                    failed_reasons,
                )

            handle_stderr(proc, checked_out_files)
            return checked_out_files
        # END paths handling
