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

    @property
    def head(self) -> "HEAD":
        """
        :return:
            :class:`~git.refs.head.HEAD` object pointing to the current head reference
        """
        return HEAD(self, "HEAD")

    def archive(
        self,
        ostream: Union[TextIO, BinaryIO],
        treeish: Optional[str] = None,
        prefix: Optional[str] = None,
        **kwargs: Any,
    ) -> Repo:
        """Archive the tree at the given revision.

        :param ostream:
            File-compatible stream object to which the archive will be written as bytes.

        :param treeish:
            The treeish name/id, defaults to active branch.

        :param prefix:
            The optional prefix to prepend to each filename in the archive.

        :param kwargs:
            Additional arguments passed to :manpage:`git-archive(1)`:

            * Use the ``format`` argument to define the kind of format. Use specialized
              ostreams to write any format supported by Python.
            * You may specify the special ``path`` keyword, which may either be a
              repository-relative path to a directory or file to place into the archive,
              or a list or tuple of multiple paths.

        :raise git.exc.GitCommandError:
            If something went wrong.

        :return:
            self
        """
        if treeish is None:
            treeish = self.head.commit
        if prefix and "prefix" not in kwargs:
            kwargs["prefix"] = prefix
        kwargs["output_stream"] = ostream
        path = kwargs.pop("path", [])
        path = cast(Union[PathLike, List[PathLike], Tuple[PathLike, ...]], path)
        if not isinstance(path, (tuple, list)):
            path = [path]
        # END ensure paths is list (or tuple)
        self.git.archive("--", treeish, *path, **kwargs)
        return self

    rev_parse = rev_parse
