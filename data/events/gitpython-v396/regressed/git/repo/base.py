from __future__ import annotations

import gc
import logging
import os
import os.path as osp
from pathlib import Path
import re
import shlex
import sys
import warnings

import gitdb
from gitdb.db.loose import LooseObjectDB
from gitdb.exc import BadObject

from git.cmd import Git, handle_process_output
from git.compat import defenc, safe_decode
from git.config import GitConfigParser
from git.db import GitCmdObjectDB
from git.exc import (
    GitCommandError,
    InvalidGitRepositoryError,
    NoSuchPathError,
)
from git.index import IndexFile
from git.objects import Submodule, RootModule, Commit
from git.refs import HEAD, Head, Reference, TagReference
from git.remote import Remote, add_progress, to_progress_instance
from git.util import (
    Actor,
    cygpath,
    expand_path,
    finalize_process,
    hex_to_bin,
    remove_password_if_present,
)

from .fun import (
    find_submodule_git_dir,
    find_worktree_git_dir,
    is_git_dir,
    rev_parse,
    touch,
)

from git.types import (
    CallableProgress,
    Commit_ish,
    Lit_config_levels,
    PathLike,
    TBD,
    Tree_ish,
    assert_never,
)
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    TYPE_CHECKING,
    TextIO,
    Tuple,
    Type,
    Union,
    cast,
)

from git.types import ConfigLevels_Tup, TypedDict

if TYPE_CHECKING:
    from git.objects import Tree
    from git.objects.submodule.base import UpdateProgress
    from git.refs.symbolic import SymbolicReference
    from git.remote import RemoteProgress
    from git.util import IterableList

_logger = logging.getLogger(__name__)


class Repo:
    """Represents a git repository and allows you to query references, create commit
    information, generate diffs, create and clone repositories, and query the log.

    The following attributes are worth using:

    * :attr:`working_dir` is the working directory of the git command, which is the
      working tree directory if available or the ``.git`` directory in case of bare
      repositories.

    * :attr:`working_tree_dir` is the working tree directory, but will return ``None``
      if we are a bare repository.

    * :attr:`git_dir` is the ``.git`` repository directory, which is always set.
    """

    DAEMON_EXPORT_FILE = "git-daemon-export-ok"

    # Must exist, or  __del__  will fail in case we raise on `__init__()`.
    git = cast("Git", None)

    working_dir: PathLike

    # stored as string for easier processing, but annotated as path for clearer intention
    _working_tree_dir: Optional[PathLike] = None

    git_dir: PathLike

    _common_dir: PathLike = ""

    # Precompiled regex
    re_whitespace = re.compile(r"\s+")
    re_hexsha_only = re.compile(r"^[0-9A-Fa-f]{40}$")
    re_hexsha_shortened = re.compile(r"^[0-9A-Fa-f]{4,40}$")
    re_envvars = re.compile(r"(\$(\{\s?)?[a-zA-Z_]\w*(\}\s?)?|%\s?[a-zA-Z_]\w*\s?%)")
    re_author_committer_start = re.compile(r"^(author|committer)")
    re_tab_full_line = re.compile(r"^\t(.*)$")

    unsafe_git_clone_options = [
        "--upload-pack",
        "-u",
        "--config",
        "-c",
    ]

    # Invariants
    config_level: ConfigLevels_Tup = ("system", "user", "global", "repository")

    # Subclass configuration
    GitCommandWrapperType = Git

    @classmethod
    def _clone(
        cls,
        git: "Git",
        url: PathLike,
        path: PathLike,
        odb_default_type: Type[GitCmdObjectDB],
        progress: Union["RemoteProgress", "UpdateProgress", Callable[..., "RemoteProgress"], None] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        odbt = kwargs.pop("odbt", odb_default_type)

        # url may be a path and this has no effect if it is a string
        url = os.fspath(url)
        path = os.fspath(path)

        ## A bug win cygwin's Git, when `--bare` or `--separate-git-dir`
        #  it prepends the cwd or(?) the `url` into the `path, so::
        #        git clone --bare  /cygwin/d/foo.git  C:\\Work
        #  becomes::
        #        git clone --bare  /cygwin/d/foo.git  /cygwin/d/C:\\Work
        #
        clone_path = Git.polish_url(path) if Git.is_cygwin() and "bare" in kwargs else path
        sep_dir = kwargs.get("separate_git_dir")
        if sep_dir:
            kwargs["separate_git_dir"] = Git.polish_url(sep_dir)
        multi = None
        if multi_options:
            multi = shlex.split(" ".join(multi_options))

        if not allow_unsafe_protocols:
            Git.check_unsafe_protocols(url)
        if not allow_unsafe_options:
            Git.check_unsafe_options(options=list(kwargs.keys()), unsafe_options=cls.unsafe_git_clone_options)
        if not allow_unsafe_options and multi:
            Git.check_unsafe_options(options=multi, unsafe_options=cls.unsafe_git_clone_options)

        proc = git.clone(
            multi,
            "--",
            Git.polish_url(url),
            clone_path,
            with_extended_output=True,
            as_process=True,
            v=True,
            universal_newlines=True,
            **add_progress(kwargs, git, progress),
        )
        if progress:
            handle_process_output(
                proc,
                None,
                to_progress_instance(progress).new_message_handler(),
                finalize_process,
                decode_streams=False,
            )
        else:
            (stdout, stderr) = proc.communicate()
            cmdline = getattr(proc, "args", "")
            cmdline = remove_password_if_present(cmdline)

            _logger.debug("Cmd(%s)'s unused stdout: %s", cmdline, stdout)
            finalize_process(proc, stderr=stderr)

        # Our git command could have a different working dir than our actual
        # environment, hence we prepend its working dir if required.
        if not osp.isabs(path):
            path = osp.join(git._working_dir, path) if git._working_dir is not None else path

        repo = cls(path, odbt=odbt)

        # Retain env values that were passed to _clone().
        repo.git.update_environment(**git.environment())

        # Adjust remotes - there may be operating systems which use backslashes, These
        # might be given as initial paths, but when handling the config file that
        # contains the remote from which we were clones, git stops liking it as it will
        # escape the backslashes. Hence we undo the escaping just to be sure.
        if repo.remotes:
            with repo.remotes[0].config_writer as writer:
                writer.set_value("url", Git.polish_url(repo.remotes[0].url))
        # END handle remote repo
        return repo

    @classmethod
    def clone_from(
        cls,
        url: PathLike,
        to_path: PathLike,
        progress: CallableProgress = None,
        env: Optional[Mapping[str, str]] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Create a clone from the given URL.

        :param url:
            Valid git url, see: https://git-scm.com/docs/git-clone#URLS

        :param to_path:
            Path to which the repository should be cloned to.

        :param progress:
            See :meth:`Remote.push <git.remote.Remote.push>`.

        :param env:
            Optional dictionary containing the desired environment variables.

            Note: Provided variables will be used to update the execution environment
            for ``git``. If some variable is not specified in `env` and is defined in
            :attr:`os.environ`, value from :attr:`os.environ` will be used. If you want
            to unset some variable, consider providing empty string as its value.

        :param multi_options:
            See the :meth:`clone` method.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            See the :meth:`clone` method.

        :return:
            :class:`Repo` instance pointing to the cloned directory.
        """
        git = cls.GitCommandWrapperType(os.getcwd())
        if env is not None:
            git.update_environment(**env)
        return cls._clone(
            git,
            url,
            to_path,
            GitCmdObjectDB,
            progress,  # type: ignore[arg-type]
            multi_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    rev_parse = rev_parse
