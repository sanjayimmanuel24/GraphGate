# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
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

log = logging.getLogger(__name__)


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

    @property
    def common_dir(self) -> PathLike:
        """
        :return: The git dir that holds everything except possibly HEAD,
            FETCH_HEAD, ORIG_HEAD, COMMIT_EDITMSG, index, and logs/."""
        return self._common_dir or self.git_dir

    # alias for references
    refs = references

    # alias for heads
    branches = heads

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

        # when pathlib.Path or other classbased path is passed
        if not isinstance(path, str):
            path = str(path)

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
            Git.check_unsafe_protocols(str(url))
        if not allow_unsafe_options and multi_options:
            Git.check_unsafe_options(options=multi_options, unsafe_options=cls.unsafe_git_clone_options)

        proc = git.clone(
            multi,
            "--",
            Git.polish_url(str(url)),
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

            log.debug("Cmd(%s)'s unused stdout: %s", cmdline, stdout)
            finalize_process(proc, stderr=stderr)

        # our git command could have a different working dir than our actual
        # environment, hence we prepend its working dir if required
        if not osp.isabs(path):
            path = osp.join(git._working_dir, path) if git._working_dir is not None else path

        repo = cls(path, odbt=odbt)

        # retain env values that were passed to _clone()
        repo.git.update_environment(**git.environment())

        # adjust remotes - there may be operating systems which use backslashes,
        # These might be given as initial paths, but when handling the config file
        # that contains the remote from which we were clones, git stops liking it
        # as it will escape the backslashes. Hence we undo the escaping just to be
        # sure
        if repo.remotes:
            with repo.remotes[0].config_writer as writer:
                writer.set_value("url", Git.polish_url(repo.remotes[0].url))
        # END handle remote repo
        return repo

    def clone(
        self,
        path: PathLike,
        progress: Optional[Callable] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Create a clone from this repository.

        :param path: is the full path of the new repo (traditionally ends with ./<name>.git).
        :param progress: See 'git.remote.Remote.push'.
        :param multi_options: A list of Clone options that can be provided multiple times.  One
            option per list item which is passed exactly as specified to clone.
            For example ['--config core.filemode=false', '--config core.ignorecase',
            '--recurse-submodule=repo1_path', '--recurse-submodule=repo2_path']
        :param allow_unsafe_protocols: Allow unsafe protocols to be used, like ext
        :param allow_unsafe_options: Allow unsafe options to be used, like --upload-pack
        :param kwargs:
            * odbt = ObjectDatabase Type, allowing to determine the object database
              implementation used by the returned Repo instance
            * All remaining keyword arguments are given to the git-clone command

        :return: ``git.Repo`` (the newly cloned repo)"""
        return self._clone(
            self.git,
            self.common_dir,
            path,
            type(self.odb),
            progress,
            multi_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    @classmethod
    def clone_from(
        cls,
        url: PathLike,
        to_path: PathLike,
        progress: Optional[Callable] = None,
        env: Optional[Mapping[str, str]] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Create a clone from the given URL

        :param url: valid git url, see http://www.kernel.org/pub/software/scm/git/docs/git-clone.html#URLS
        :param to_path: Path to which the repository should be cloned to
        :param progress: See 'git.remote.Remote.push'.
        :param env: Optional dictionary containing the desired environment variables.
            Note: Provided variables will be used to update the execution
            environment for `git`. If some variable is not specified in `env`
            and is defined in `os.environ`, value from `os.environ` will be used.
            If you want to unset some variable, consider providing empty string
            as its value.
        :param multi_options: See ``clone`` method
        :param allow_unsafe_protocols: Allow unsafe protocols to be used, like ext
        :param allow_unsafe_options: Allow unsafe options to be used, like --upload-pack
        :param kwargs: see the ``clone`` method
        :return: Repo instance pointing to the cloned directory"""
        git = cls.GitCommandWrapperType(os.getcwd())
        if env is not None:
            git.update_environment(**env)
        return cls._clone(
            git,
            url,
            to_path,
            GitCmdObjectDB,
            progress,
            multi_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    rev_parse = rev_parse
