# cmd.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from __future__ import annotations
import re
from contextlib import contextmanager
import io
import logging
import os
import signal
from subprocess import call, Popen, PIPE, DEVNULL
import subprocess
import threading
from textwrap import dedent

from git.compat import (
    defenc,
    force_bytes,
    safe_decode,
    is_posix,
    is_win,
)
from git.exc import CommandError
from git.util import is_cygwin_git, cygpath, expand_path, remove_password_if_present

from .exc import GitCommandError, GitCommandNotFound, UnsafeOptionError, UnsafeProtocolError
from .util import (
    LazyMixin,
    stream_copy,
)

from typing import (
    Any,
    AnyStr,
    BinaryIO,
    Callable,
    Dict,
    IO,
    Iterator,
    List,
    Mapping,
    Sequence,
    TYPE_CHECKING,
    TextIO,
    Tuple,
    Union,
    cast,
    overload,
)

from git.types import PathLike, Literal, TBD

if TYPE_CHECKING:
    from git.repo.base import Repo
    from git.diff import DiffIndex

execute_kwargs = {
    "istream",
    "with_extended_output",
    "with_exceptions",
    "as_process",
    "stdout_as_string",
    "output_stream",
    "with_stdout",
    "kill_after_timeout",
    "universal_newlines",
    "shell",
    "env",
    "max_chunk_size",
    "strip_newline_in_stdout",
}


def dashify(string: str) -> str:
    return string.replace("_", "-")


class Git(LazyMixin):

    """
    The Git class manages communication with the Git binary.

    It provides a convenient interface to calling the Git binary, such as in::

     g = Git( git_dir )
     g.init()                   # calls 'git init' program
     rval = g.ls_files()        # calls 'git ls-files' program

    ``Debugging``
        Set the GIT_PYTHON_TRACE environment variable print each invocation
        of the command to stdout.
        Set its value to 'full' to see details about the returned values.
    """

    __slots__ = (
        "_working_dir",
        "cat_file_all",
        "cat_file_header",
        "_version_info",
        "_git_options",
        "_persistent_git_options",
        "_environment",
    )

    _excluded_ = ("cat_file_all", "cat_file_header", "_version_info")

    re_unsafe_protocol = re.compile("(.+)::.+")

    git_exec_name = "git"  # default that should work on linux and windows

    # Enables debugging of GitPython's git commands
    GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

    # If True, a shell will be used when executing git commands.
    # This should only be desirable on Windows, see https://github.com/gitpython-developers/GitPython/pull/126
    # and check `git/test_repo.py:TestRepo.test_untracked_files()` TC for an example where it is required.
    # Override this value using `Git.USE_SHELL = True`
    USE_SHELL = False

    # Provide the full path to the git executable. Otherwise it assumes git is in the path
    _git_exec_env_var = "GIT_PYTHON_GIT_EXECUTABLE"
    _refresh_env_var = "GIT_PYTHON_REFRESH"
    GIT_PYTHON_GIT_EXECUTABLE = None

    @classmethod
    def check_unsafe_options(cls, options: List[str], unsafe_options: List[str]) -> None:
        """
        Check for unsafe options.
        """
        # Options can be of the form `foo` or `--foo bar` `--foo=bar`,
        # so we need to check if they start with "--foo" or if they are equal to "foo".
        bare_unsafe_options = [
            option.lstrip("-")
            for option in unsafe_options
        ]
        for option in options:
            for unsafe_option, bare_option in zip(unsafe_options, bare_unsafe_options):
                if option.startswith(unsafe_option) or option == bare_option:
                    raise UnsafeOptionError(
                        f"{unsafe_option} is not allowed, use `allow_unsafe_options=True` to allow it."
                    )

    def __getattr__(self, name: str) -> Any:
        """A convenience method as it allows to call the command as if it was
        an object.

        :return: Callable object that will execute call _call_process with your arguments."""
        if name[0] == "_":
            return LazyMixin.__getattr__(self, name)
        return lambda *args, **kwargs: self._call_process(name, *args, **kwargs)

    def transform_kwarg(self, name: str, value: Any, split_single_char_options: bool) -> List[str]:
        if len(name) == 1:
            if value is True:
                return ["-%s" % name]
            elif value not in (False, None):
                if split_single_char_options:
                    return ["-%s" % name, "%s" % value]
                else:
                    return ["-%s%s" % (name, value)]
        else:
            if value is True:
                return ["--%s" % dashify(name)]
            elif value is not False and value is not None:
                return ["--%s=%s" % (dashify(name), value)]
        return []

    def transform_kwargs(self, split_single_char_options: bool = True, **kwargs: Any) -> List[str]:
        """Transforms Python style kwargs into git command line options."""
        args = []
        for k, v in kwargs.items():
            if isinstance(v, (list, tuple)):
                for value in v:
                    args += self.transform_kwarg(k, value, split_single_char_options)
            else:
                args += self.transform_kwarg(k, v, split_single_char_options)
        return args

    @classmethod
    def _unpack_args(cls, arg_list: Sequence[str]) -> List[str]:

        outlist = []
        if isinstance(arg_list, (list, tuple)):
            for arg in arg_list:
                outlist.extend(cls._unpack_args(arg))
        else:
            outlist.append(str(arg_list))

        return outlist

    @overload
    def _call_process(self, method: str, *args: None, **kwargs: None) -> str:
        ...  # if no args given, execute called with all defaults

    @overload
    def _call_process(
        self,
        method: str,
        istream: int,
        as_process: Literal[True],
        *args: Any,
        **kwargs: Any,
    ) -> "Git.AutoInterrupt":
        ...

    @overload
    def _call_process(
        self, method: str, *args: Any, **kwargs: Any
    ) -> Union[str, bytes, Tuple[int, Union[str, bytes], str], "Git.AutoInterrupt"]:
        ...

    def _call_process(
        self, method: str, *args: Any, **kwargs: Any
    ) -> Union[str, bytes, Tuple[int, Union[str, bytes], str], "Git.AutoInterrupt"]:
        """Run the given git command with the specified arguments and return
        the result as a String

        :param method:
            is the command. Contained "_" characters will be converted to dashes,
            such as in 'ls_files' to call 'ls-files'.

        :param args:
            is the list of arguments. If None is included, it will be pruned.
            This allows your commands to call git more conveniently as None
            is realized as non-existent

        :param kwargs:
            It contains key-values for the following:
            - the :meth:`execute()` kwds, as listed in :var:`execute_kwargs`;
            - "command options" to be converted by :meth:`transform_kwargs()`;
            - the `'insert_kwargs_after'` key which its value must match one of ``*args``
            and any cmd-options will be appended after the matched arg.

        Examples::

            git.rev_list('master', max_count=10, header=True)

        turns into::

           git rev-list max-count 10 --header master

        :return: Same as ``execute``
                 if no args given used execute default (esp. as_process = False, stdout_as_string = True)
                 and return str"""
        # Handle optional arguments prior to calling transform_kwargs
        # otherwise these'll end up in args, which is bad.
        exec_kwargs = {k: v for k, v in kwargs.items() if k in execute_kwargs}
        opts_kwargs = {k: v for k, v in kwargs.items() if k not in execute_kwargs}

        insert_after_this_arg = opts_kwargs.pop("insert_kwargs_after", None)

        # Prepare the argument list

        opt_args = self.transform_kwargs(**opts_kwargs)
        ext_args = self._unpack_args([a for a in args if a is not None])

        if insert_after_this_arg is None:
            args_list = opt_args + ext_args
        else:
            try:
                index = ext_args.index(insert_after_this_arg)
            except ValueError as err:
                raise ValueError(
                    "Couldn't find argument '%s' in args %s to insert cmd options after"
                    % (insert_after_this_arg, str(ext_args))
                ) from err
            # end handle error
            args_list = ext_args[: index + 1] + opt_args + ext_args[index + 1 :]
        # end handle opts_kwargs

        call = [self.GIT_PYTHON_GIT_EXECUTABLE]

        # add persistent git options
        call.extend(self._persistent_git_options)

        # add the git options, then reset to empty
        # to avoid side_effects
        call.extend(self._git_options)
        self._git_options = ()

        call.append(dashify(method))
        call.extend(args_list)

        return self.execute(call, **exec_kwargs)
