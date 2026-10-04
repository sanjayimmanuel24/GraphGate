"""Module implementing a remote object allowing easy access to git remotes."""

import contextlib
import logging
import re

from git.cmd import Git, handle_process_output
from git.compat import defenc, force_text
from git.config import GitConfigParser, SectionConstraint, cp
from git.exc import GitCommandError
from git.refs import Head, Reference, RemoteReference, SymbolicReference, TagReference
from git.util import (
    CallableRemoteProgress,
    IterableList,
    IterableObj,
    LazyMixin,
    RemoteProgress,
    join_path,
)

from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    NoReturn,
    Optional,
    Sequence,
    TYPE_CHECKING,
    Type,
    Union,
    cast,
    overload,
)

from git.types import AnyGitObject, Literal, PathLike

if TYPE_CHECKING:
    from git.objects.commit import Commit
    from git.objects.submodule.base import UpdateProgress
    from git.repo.base import Repo


def add_progress(
    kwargs: Any,
    git: Git,
    progress: Union[RemoteProgress, "UpdateProgress", Callable[..., RemoteProgress], None],
) -> Any:
    """Add the ``--progress`` flag to the given `kwargs` dict if supported by the git
    command.

    :note:
        If the actual progress in the given progress instance is not given, we do not
        request any progress.

    :return:
        Possibly altered `kwargs`
    """
    if progress is not None:
        v = git.version_info[:2]
        if v >= (1, 7):
            kwargs["progress"] = True
        # END handle --progress
    # END handle progress
    return kwargs


class Remote(LazyMixin, IterableObj):
    """Provides easy read and write access to a git remote.

    Everything not part of this interface is considered an option for the current
    remote, allowing constructs like ``remote.pushurl`` to query the pushurl.

    :note:
        When querying configuration, the configuration accessor will be cached to speed
        up subsequent accesses.
    """

    __slots__ = ("repo", "name", "_config_reader")

    _id_attribute_ = "name"

    unsafe_git_fetch_options = [
        # https://git-scm.com/docs/git-fetch#Documentation/git-fetch.txt---upload-packltupload-packgt
        "--upload-pack",
    ]
    unsafe_git_pull_options = [
        # https://git-scm.com/docs/git-pull#Documentation/git-pull.txt---upload-packltupload-packgt
        "--upload-pack"
    ]
    unsafe_git_push_options = [
        # https://git-scm.com/docs/git-push#Documentation/git-push.txt---execltgit-receive-packgt
        "--receive-pack",
        "--exec",
    ]

    url: str  # Obtained dynamically from _config_reader. See __getattr__ below.

    def fetch(
        self,
        refspec: Union[str, List[str], None] = None,
        progress: Union[RemoteProgress, None, "UpdateProgress"] = None,
        verbose: bool = True,
        kill_after_timeout: Union[None, float] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> IterableList[FetchInfo]:
        """Fetch the latest changes for this remote.

        :param refspec:
            A "refspec" is used by fetch and push to describe the mapping
            between remote ref and local ref. They are combined with a colon in
            the format ``<src>:<dst>``, preceded by an optional plus sign, ``+``.
            For example: ``git fetch $URL refs/heads/master:refs/heads/origin`` means
            "grab the master branch head from the $URL and store it as my origin
            branch head". And ``git push $URL refs/heads/master:refs/heads/to-upstream``
            means "publish my master branch head as to-upstream branch at $URL".
            See also :manpage:`git-push(1)`.

            Taken from the git manual, :manpage:`gitglossary(7)`.

            Fetch supports multiple refspecs (as the underlying :manpage:`git-fetch(1)`
            does) - supplying a list rather than a string for 'refspec' will make use of
            this facility.

        :param progress:
            See the :meth:`push` method.

        :param verbose:
            Boolean for verbose output.

        :param kill_after_timeout:
            To specify a timeout in seconds for the git command, after which the process
            should be killed. It is set to ``None`` by default.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-fetch(1)`.

        :return:
            IterableList(FetchInfo, ...) list of :class:`FetchInfo` instances providing
            detailed information about the fetch results

        :note:
            As fetch does not provide progress information to non-ttys, we cannot make
            it available here unfortunately as in the :meth:`push` method.
        """
        if refspec is None:
            # No argument refspec, then ensure the repo's config has a fetch refspec.
            self._assert_refspec()

        kwargs = add_progress(kwargs, self.repo.git, progress)
        if isinstance(refspec, list):
            args: Sequence[Optional[str]] = refspec
        else:
            args = [refspec]

        if not allow_unsafe_protocols:
            for ref in args:
                if ref:
                    Git.check_unsafe_protocols(ref)

        if not allow_unsafe_options:
            Git.check_unsafe_options(options=list(kwargs.keys()), unsafe_options=self.unsafe_git_fetch_options)

        proc = self.repo.git.fetch(
            "--", self, *args, as_process=True, with_stdout=False, universal_newlines=True, v=verbose, **kwargs
        )
        res = self._get_fetch_info_from_stderr(proc, progress, kill_after_timeout=kill_after_timeout)
        if hasattr(self.repo.odb, "update_cache"):
            self.repo.odb.update_cache()
        return res
