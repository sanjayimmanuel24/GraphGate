from __future__ import annotations

import contextlib
import io
import itertools
import logging
import os
import re
import signal
import subprocess
from subprocess import DEVNULL, PIPE, Popen
import sys
from textwrap import dedent
import threading
import warnings

from git.compat import defenc, force_bytes, safe_decode
from git.exc import (
    CommandError,
    GitCommandError,
    GitCommandNotFound,
    UnsafeOptionError,
    UnsafeProtocolError,
)
from git.util import (
    cygpath,
    expand_path,
    is_cygwin_git,
    patch_env,
    remove_password_if_present,
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
    Optional,
    Sequence,
    TYPE_CHECKING,
    TextIO,
    Tuple,
    Union,
    cast,
    overload,
)

if sys.version_info >= (3, 10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias

from git.types import Literal, PathLike, TBD

if TYPE_CHECKING:
    from git.diff import DiffIndex
    from git.repo.base import Repo


def dashify(string: str) -> str:
    return string.replace("_", "-")


class Git(metaclass=_GitMeta):
    """The Git class manages communication with the Git binary.

    It provides a convenient interface to calling the Git binary, such as in::

     g = Git( git_dir )
     g.init()                   # calls 'git init' program
     rval = g.ls_files()        # calls 'git ls-files' program

    Debugging:

    * Set the :envvar:`GIT_PYTHON_TRACE` environment variable to print each invocation
      of the command to stdout.
    * Set its value to ``full`` to see details about the returned values.
    """

    __slots__ = (
        "_working_dir",
        "cat_file_all",
        "cat_file_header",
        "_version_info",
        "_version_info_token",
        "_git_options",
        "_persistent_git_options",
        "_environment",
    )

    _excluded_ = (
        "cat_file_all",
        "cat_file_header",
        "_version_info",
        "_version_info_token",
    )

    re_unsafe_protocol = re.compile(r"(.+)::.+")

    unsafe_git_ls_remote_options = [
        "--upload-pack",
    ]

    git_exec_name = "git"

    GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

    USE_SHELL: bool = False

    _git_exec_env_var = "GIT_PYTHON_GIT_EXECUTABLE"
    _refresh_env_var = "GIT_PYTHON_REFRESH"

    GIT_PYTHON_GIT_EXECUTABLE = None

    _refresh_token = object()  # Since None would match an initial _version_info_token.

    @classmethod
    def _canonicalize_option_name(cls, option: str) -> str:
        """Return the option name used for unsafe-option checks.

        Examples:
            ``"--upload-pack=/tmp/helper"`` -> ``"upload-pack"``
            ``"upload_pack"`` -> ``"upload-pack"``
            ``"--config core.filemode=false"`` -> ``"config"``
        """
        option_name = option.lstrip("-").split("=", 1)[0]
        option_tokens = option_name.split(None, 1)
        if not option_tokens:
            return ""
        return dashify(option_tokens[0])

    @classmethod
    def check_unsafe_options(cls, options: List[str], unsafe_options: List[str]) -> None:
        """Raise :class:`~git.exc.UnsafeOptionError` for blocked option spellings.

        In addition to exact matches, this rejects abbreviated long options accepted
        by Git (for example, ``--upl`` for ``--upload-pack``) and unsafe short options
        whose values are joined to the same token, including after clusterable flags
        (for example, ``-uVALUE`` and ``-fuVALUE``).

        A list containing only bare names is treated as normalized keyword arguments,
        so multi-character names such as ``upload_p`` are checked as long-option
        abbreviations. If any item starts with ``-``, the list is treated as tokenized
        command-line input: bare items can be option values and are not checked as
        abbreviations. Thus ``["--origin", "upload"]`` is allowed. Single-dash options
        use short-option parsing rather than broad prefix matching, preserving safe
        attached values such as ``-oupstream`` and ``-bcurrent``.
        """
        # Options can be of the form `foo`, `--foo`, `--foo bar`, or `--foo=bar`.
        # Git accepts any unambiguous prefix of a long option, so an abbreviated
        # spelling such as `--upl` for `--upload-pack` must be rejected too. An
        # option is unsafe if its canonical name is a prefix of any blocked
        # option's canonical name. Only long options and multi-character kwargs
        # can be abbreviations; single-character short options remain exact-match
        # only.
        canonical_unsafe_options = {cls._canonicalize_option_name(option): option for option in unsafe_options}
        unsafe_short_options = {
            canonical: option
            for canonical, option in canonical_unsafe_options.items()
            if option.startswith("-") and not option.startswith("--") and len(canonical) == 1
        }
        # These value-less Git flags can be clustered before another short option
        # (for example, ``-fuVALUE``). Stop at any other character because it may
        # begin an attached value, as ``o`` does in the safe option ``-oupstream``.
        clusterable_short_options = frozenset("46flnqsv")
        options_are_kwargs = all(not option.startswith("-") for option in options)
        for option in options:
            candidate = cls._canonicalize_option_name(option)
            if not candidate:
                continue
            unsafe_option = canonical_unsafe_options.get(candidate)
            if unsafe_option is not None:
                raise UnsafeOptionError(f"{unsafe_option} is not allowed, use `allow_unsafe_options=True` to allow it.")
            option_token = option.split("=", 1)[0].split(None, 1)[0]
            if option_token.startswith("-") and not option_token.startswith("--"):
                for option_char in option_token[1:]:
                    unsafe_option = unsafe_short_options.get(option_char)
                    if unsafe_option is not None:
                        raise UnsafeOptionError(
                            f"{unsafe_option} is not allowed, use `allow_unsafe_options=True` to allow it."
                        )
                    if option_char not in clusterable_short_options:
                        break
            if not (option.startswith("--") or (options_are_kwargs and len(candidate) > 1)):
                continue
            for canonical, unsafe_option in canonical_unsafe_options.items():
                if canonical.startswith(candidate):
                    raise UnsafeOptionError(
                        f"{unsafe_option} is not allowed, use `allow_unsafe_options=True` to allow it."
                    )

    @classmethod
    def _option_candidates(cls, args: Sequence[Any] = (), kwargs: Optional[Mapping[str, Any]] = None) -> List[str]:
        """Collect possible option spellings before command-line transformation."""
        options = [
            option for option in cls._unpack_args([arg for arg in args if arg is not None]) if option.startswith("-")
        ]
        if kwargs:
            split_single_char_options = kwargs.get("split_single_char_options", True)
            for key, value in kwargs.items():
                values = value if isinstance(value, (list, tuple)) else (value,)
                if any(value is True or (value is not False and value is not None) for value in values):
                    key = str(key)
                    options.append(f"-{key}" if len(key) == 1 else f"--{dashify(key)}")
                    if len(key) == 1 and split_single_char_options:
                        options.extend(
                            str(value)
                            for value in values
                            if value is not True and value not in (False, None) and str(value).startswith("-")
                        )
        return options

    AutoInterrupt: TypeAlias = _AutoInterrupt

    CatFileContentStream: TypeAlias = _CatFileContentStream

    def __getattr__(self, name: str) -> Any:
        """A convenience method as it allows to call the command as if it was an object.

        :return:
            Callable object that will execute call :meth:`_call_process` with your
            arguments.
        """
        if name.startswith("_"):
            return super().__getattribute__(name)
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
        """Transform Python-style kwargs into git command line options."""
        args = []
        for k, v in kwargs.items():
            if isinstance(v, (list, tuple)):
                for value in v:
                    args += self.transform_kwarg(k, value, split_single_char_options)
            else:
                args += self.transform_kwarg(k, v, split_single_char_options)
        return args

    @overload
    def _call_process(
        self, method: str, *args: None, **kwargs: None
    ) -> str: ...  # If no args were given, execute the call with all defaults.

    @overload
    def _call_process(
        self,
        method: str,
        istream: int,
        as_process: Literal[True],
        *args: Any,
        **kwargs: Any,
    ) -> "Git.AutoInterrupt": ...

    @overload
    def _call_process(
        self, method: str, *args: Any, **kwargs: Any
    ) -> Union[str, bytes, Tuple[int, Union[str, bytes], str], "Git.AutoInterrupt"]: ...

    def _call_process(
        self, method: str, *args: Any, **kwargs: Any
    ) -> Union[str, bytes, Tuple[int, Union[str, bytes], str], "Git.AutoInterrupt"]:
        """Run the given git command with the specified arguments and return the result
        as a string.

        :param method:
            The command. Contained ``_`` characters will be converted to hyphens, such
            as in ``ls_files`` to call ``ls-files``.

        :param args:
            The list of arguments. If ``None`` is included, it will be pruned.
            This allows your commands to call git more conveniently, as ``None`` is
            realized as non-existent.

        :param kwargs:
            Contains key-values for the following:

            - The :meth:`execute()` kwds, as listed in ``execute_kwargs``.
            - "Command options" to be converted by :meth:`transform_kwargs`.
            - The ``insert_kwargs_after`` key which its value must match one of
              ``*args``.

            It also contains any command options, to be appended after the matched arg.

        Examples::

            git.rev_list('master', max_count=10, header=True)

        turns into::

            git rev-list --max-count=10 --header master

        :return:
            Same as :meth:`execute`. If no args are given, used :meth:`execute`'s
            default (especially ``as_process = False``, ``stdout_as_string = True``) and
            return :class:`str`.
        """
        # Handle optional arguments prior to calling transform_kwargs.
        # Otherwise these'll end up in args, which is bad.
        exec_kwargs = {k: v for k, v in kwargs.items() if k in execute_kwargs}
        opts_kwargs = {k: v for k, v in kwargs.items() if k not in execute_kwargs}

        insert_after_this_arg = opts_kwargs.pop("insert_kwargs_after", None)

        # Prepare the argument list.

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
            # END handle error
            args_list = ext_args[: index + 1] + opt_args + ext_args[index + 1 :]
        # END handle opts_kwargs

        call = [self.GIT_PYTHON_GIT_EXECUTABLE]

        # Add persistent git options.
        call.extend(self._persistent_git_options)

        # Add the git options, then reset to empty to avoid side effects.
        call.extend(self._git_options)
        self._git_options = ()

        call.append(dashify(method))
        call.extend(args_list)

        return self.execute(call, **exec_kwargs)
