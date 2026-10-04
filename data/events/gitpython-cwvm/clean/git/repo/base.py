# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: https://opensource.org/license/bsd-3-clause/
from __future__ import annotations
import logging
import os
import re
import shlex
import warnings

from pathlib import Path

from gitdb.db.loose import LooseObjectDB

from gitdb.exc import BadObject

from git.cmd import Git, handle_process_output
from git.compat import (
    defenc,
    safe_decode,
    is_win,
)
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
    finalize_process,
    cygpath,
    hex_to_bin,
    expand_path,
    remove_password_if_present,
)
import os.path as osp

from .fun import (
    rev_parse,
    is_git_dir,
    find_submodule_git_dir,
    touch,
    find_worktree_git_dir,
)
import gc
import gitdb

from git.types import (
    TBD,
    PathLike,
    Lit_config_levels,
    Commit_ish,
    CallableProgress,
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
    Optional,
    Sequence,
    TextIO,
    Tuple,
    Type,
    Union,
    NamedTuple,
    cast,
    TYPE_CHECKING,
)

from git.types import ConfigLevels_Tup, TypedDict

if TYPE_CHECKING:
    from git.util import IterableList
    from git.refs.symbolic import SymbolicReference
    from git.objects import Tree
    from git.objects.submodule.base import UpdateProgress
    from git.remote import RemoteProgress


class Repo(object):
    """Represents a git repository and allows you to query references,
    gather commit information, generate diffs, create and clone repositories query
    the log.

    The following attributes are worth using:

    'working_dir' is the working directory of the git command, which is the working tree
    directory if available or the .git directory in case of bare repositories

    'working_tree_dir' is the working tree directory, but will return None
    if we are a bare repository.

    'git_dir' is the .git repository directory, which is always set."""

    DAEMON_EXPORT_FILE = "git-daemon-export-ok"

    git = cast("Git", None)  # Must exist, or  __del__  will fail in case we raise on `__init__()`
    working_dir: PathLike
    _working_tree_dir: Optional[PathLike] = None
    git_dir: PathLike
    _common_dir: PathLike = ""

    # precompiled regex
    re_whitespace = re.compile(r"\s+")
    re_hexsha_only = re.compile("^[0-9A-Fa-f]{40}$")
    re_hexsha_shortened = re.compile("^[0-9A-Fa-f]{4,40}$")
    re_envvars = re.compile(r"(\$(\{\s?)?[a-zA-Z_]\w*(\}\s?)?|%\s?[a-zA-Z_]\w*\s?%)")
    re_author_committer_start = re.compile(r"^(author|committer)")
    re_tab_full_line = re.compile(r"^\t(.*)$")

    unsafe_git_clone_options = [
        # https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---upload-packltupload-packgt
        "--upload-pack",
        "-u",
        # Users can override configuration variables
        # https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---configltkeygtltvaluegt
        "--config",
        "-c",
    ]

    # invariants
    # represents the configuration level of a configuration file
    config_level: ConfigLevels_Tup = ("system", "user", "global", "repository")

    # Subclass configuration
    # Subclasses may easily bring in their own custom types by placing a constructor or type here
    GitCommandWrapperType = Git

    description = property(_get_description, _set_description, doc="the project's description")

    # alias for references
    refs = references

    # alias for heads
    branches = heads

    @property
    def head(self) -> "HEAD":
        """:return: HEAD Object pointing to the current head reference"""
        return HEAD(self, "HEAD")

    def commit(self, rev: Union[str, Commit_ish, None] = None) -> Commit:
        """The Commit object for the specified revision

        :param rev: revision specifier, see git-rev-parse for viable options.
        :return: ``git.Commit``
        """
        if rev is None:
            return self.head.commit
        return self.rev_parse(str(rev) + "^0")

    daemon_export = property(
        _get_daemon_export,
        _set_daemon_export,
        doc="If True, git-daemon may export this repository",
    )

    alternates = property(
        _get_alternates,
        _set_alternates,
        doc="Retrieve a list of alternates paths or set a list paths to be used as alternates",
    )

    rev_parse = rev_parse
