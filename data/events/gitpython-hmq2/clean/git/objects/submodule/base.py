import gc
from io import BytesIO
import logging
import ntpath
import os
import os.path as osp
import stat
import sys
import uuid
import urllib

import git
from git.cmd import Git
from git.compat import defenc
from git.config import GitConfigParser, SectionConstraint, cp
from git.exc import (
    BadName,
    InvalidGitRepositoryError,
    NoSuchPathError,
    RepositoryDirtyError,
)
from git.objects.base import IndexObject, Object
from git.objects.util import TraversableIterableObj
from git.util import (
    IterableList,
    RemoteProgress,
    join_path_native,
    rmtree,
    to_native_path_linux,
    unbare_repo,
)

from .util import (
    SubmoduleConfigParser,
    find_first_remote_branch,
    mkhead,
    sm_name,
    sm_section,
)

from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Sequence,
    TYPE_CHECKING,
    Union,
    cast,
)

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

from git.types import Commit_ish, PathLike, TBD

if TYPE_CHECKING:
    from git.index import IndexFile
    from git.objects.commit import Commit
    from git.refs import Head, RemoteReference
    from git.repo import Repo

_logger = logging.getLogger(__name__)


# IndexObject comes via the util module. It's a 'hacky' fix thanks to Python's import
# mechanism, which causes plenty of trouble if the only reason for packages and modules
# is refactoring - subpackages shouldn't depend on parent packages.
class Submodule(IndexObject, TraversableIterableObj):
    """Implements access to a git submodule. They are special in that their sha
    represents a commit in the submodule's repository which is to be checked out
    at the path of this instance.

    The submodule type does not have a string type associated with it, as it exists
    solely as a marker in the tree and index.

    All methods work in bare and non-bare repositories.
    """

    _id_attribute_ = "name"
    k_modules_file = ".gitmodules"
    k_head_option = "branch"
    k_head_default = "master"
    k_default_mode = stat.S_IFDIR | stat.S_IFLNK

    type: Literal["submodule"] = "submodule"  # type: ignore[assignment]

    __slots__ = ("_parent_commit", "_url", "_branch_path", "_name", "__weakref__")

    _cache_attrs = ("path", "_url", "_branch_path")

    @classmethod
    def _need_gitfile_submodules(cls, git: Git) -> bool:
        return git.version_info[:3] >= (1, 7, 5)

    @classmethod
    def _validated_name(cls, name: str) -> str:
        if (
            not name
            or name.startswith(("/", "\\"))
            or ntpath.splitdrive(name)[0]
            or ".." in name.replace("\\", "/").split("/")
        ):
            raise ValueError("Invalid submodule name %r" % name)
        return name

    @classmethod
    def _module_abspath(cls, parent_repo: "Repo", path: PathLike, name: str) -> PathLike:
        if cls._need_gitfile_submodules(parent_repo.git):
            return osp.join(parent_repo.git_dir, "modules", cls._validated_name(name))
        if parent_repo.working_tree_dir:
            return osp.join(parent_repo.working_tree_dir, path)
        raise NotADirectoryError()

    @classmethod
    def _clone_repo(
        cls,
        repo: "Repo",
        url: str,
        path: PathLike,
        name: str,
        allow_unsafe_options: bool = False,
        allow_unsafe_protocols: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """
        :return:
            :class:`~git.repo.base.Repo` instance of newly cloned repository.

        :param repo:
            Our parent repository.

        :param url:
            URL to clone from.

        :param path:
            Repository-relative path to the submodule checkout location.

        :param name:
            Canonical name of the submodule.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            Additional arguments given to :manpage:`git-clone(1)`.
        """
        module_abspath = cls._module_abspath(repo, path, name)
        module_checkout_path = module_abspath
        if cls._need_gitfile_submodules(repo.git):
            kwargs["separate_git_dir"] = module_abspath
            module_abspath_dir = osp.dirname(module_abspath)
            if not osp.isdir(module_abspath_dir):
                os.makedirs(module_abspath_dir)
            module_checkout_path = osp.join(repo.working_tree_dir, path)  # type: ignore[arg-type]

        if url.startswith("../"):
            remote_name = cast("RemoteReference", repo.active_branch.tracking_branch()).remote_name
            repo_remote_url = repo.remote(remote_name).url
            url = os.path.join(repo_remote_url, url)

        clone = git.Repo.clone_from(
            url,
            module_checkout_path,
            allow_unsafe_options=allow_unsafe_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            **kwargs,
        )
        if cls._need_gitfile_submodules(repo.git):
            cls._write_git_file_and_module_config(module_checkout_path, module_abspath)

        return clone

    def update(
        self,
        recursive: bool = False,
        init: bool = True,
        to_latest_revision: bool = False,
        progress: Union["UpdateProgress", None] = None,
        dry_run: bool = False,
        force: bool = False,
        keep_going: bool = False,
        env: Union[Mapping[str, str], None] = None,
        clone_multi_options: Union[Sequence[TBD], None] = None,
        allow_unsafe_options: bool = False,
        allow_unsafe_protocols: bool = False,
    ) -> "Submodule":
        """Update the repository of this submodule to point to the checkout we point at
        with the binsha of this instance.

        :param recursive:
            If ``True``, we will operate recursively and update child modules as well.

        :param init:
            If ``True``, the module repository will be cloned into place if necessary.

        :param to_latest_revision:
            If ``True``, the submodule's sha will be ignored during checkout. Instead,
            the remote will be fetched, and the local tracking branch updated. This only
            works if we have a local tracking branch, which is the case if the remote
            repository had a master branch, or if the ``branch`` option was specified
            for this submodule and the branch existed remotely.

        :param progress:
            :class:`UpdateProgress` instance, or ``None`` if no progress should be
            shown.

        :param dry_run:
            If ``True``, the operation will only be simulated, but not performed.
            All performed operations are read-only.

        :param force:
            If ``True``, we may reset heads even if the repository in question is dirty.
            Additionally we will be allowed to set a tracking branch which is ahead of
            its remote branch back into the past or the location of the remote branch.
            This will essentially 'forget' commits.

            If ``False``, local tracking branches that are in the future of their
            respective remote branches will simply not be moved.

        :param keep_going:
            If ``True``, we will ignore but log all errors, and keep going recursively.
            Unless `dry_run` is set as well, `keep_going` could cause
            subsequent/inherited errors you wouldn't see otherwise.
            In conjunction with `dry_run`, it can be useful to anticipate all errors
            when updating submodules.

        :param env:
            Optional dictionary containing the desired environment variables.

            Note: Provided variables will be used to update the execution environment
            for ``git``. If some variable is not specified in `env` and is defined in
            attr:`os.environ`, value from attr:`os.environ` will be used.

            If you want to unset some variable, consider providing the empty string as
            its value.

        :param clone_multi_options:
            List of :manpage:`git-clone(1)` options.
            Please see :meth:`Repo.clone <git.repo.base.Repo.clone>` for details.
            They only take effect with the `init` option.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :note:
            Does nothing in bare repositories.

        :note:
            This method is definitely not atomic if `recursive` is ``True``.

        :return:
            self
        """
        if self.repo.bare:
            return self
        # END pass in bare mode

        if progress is None:
            progress = UpdateProgress()
        # END handle progress
        prefix = ""
        if dry_run:
            prefix = "DRY-RUN: "
        # END handle prefix

        # To keep things plausible in dry-run mode.
        if dry_run:
            mrepo = None
        # END init mrepo

        def fetch_remotes(module_repo: "Repo") -> None:
            rmts = module_repo.remotes
            len_rmts = len(rmts)
            for i, remote in enumerate(rmts):
                op = FETCH
                if i == 0:
                    op |= BEGIN
                # END handle start

                progress.update(
                    op,
                    i,
                    len_rmts,
                    prefix + "Fetching remote %s of submodule %r" % (remote, self.name),
                )
                # ===============================
                if not dry_run:
                    remote.fetch(progress=progress)
                # END handle dry-run
                # ===============================
                if i == len_rmts - 1:
                    op |= END
                # END handle end
                progress.update(
                    op,
                    i,
                    len_rmts,
                    prefix + "Done fetching remote of submodule %r" % self.name,
                )
            # END fetch new data

        try:
            self._validated_name(self.name)

            # ENSURE REPO IS PRESENT AND UP-TO-DATE
            #######################################
            try:
                mrepo = self.module()
                fetch_remotes(mrepo)
            except InvalidGitRepositoryError:
                mrepo = None
                if not init:
                    return self
                # END early abort if init is not allowed

                checkout_module_abspath = self.abspath
                module_abspath = self._module_abspath(self.repo, self.path, self.name)

                # ``git submodule deinit`` leaves the repository in
                # ``.git/modules`` and empties the checkout. Reconnect that retained
                # repository instead of trying to clone over it.
                if not dry_run and osp.isdir(module_abspath):
                    try:
                        git.Repo(module_abspath)
                    except InvalidGitRepositoryError:
                        pass
                    else:
                        if osp.lexists(checkout_module_abspath) and (
                            osp.islink(checkout_module_abspath)
                            or not osp.isdir(checkout_module_abspath)
                            or os.listdir(checkout_module_abspath)
                        ):
                            raise OSError(
                                "Module directory at %r does already exist and is non-empty" % checkout_module_abspath
                            )
                        os.makedirs(checkout_module_abspath, exist_ok=True)
                        self._write_git_file_and_module_config(checkout_module_abspath, module_abspath)
                        mrepo = git.Repo(checkout_module_abspath)
                        mrepo.head.reset(mrepo.head.commit, index=True, working_tree=True)
                        fetch_remotes(mrepo)
                        with self.repo.config_writer() as writer:
                            writer.set_value(sm_section(self.name), "url", self.url)

                if mrepo is None:
                    # There is no git-repository yet - but delete empty paths.
                    if not dry_run and osp.isdir(checkout_module_abspath):
                        try:
                            os.rmdir(checkout_module_abspath)
                        except OSError as e:
                            raise OSError(
                                "Module directory at %r does already exist and is non-empty" % checkout_module_abspath
                            ) from e
                    # END handle directory removal

                    # Don't check it out at first - nonetheless it will create a local
                    # branch according to the remote-HEAD if possible.
                    progress.update(
                        BEGIN | CLONE,
                        0,
                        1,
                        prefix
                        + "Cloning url '%s' to '%s' in submodule %r" % (self.url, checkout_module_abspath, self.name),
                    )
                    if not dry_run:
                        if self.url.startswith("."):
                            url = urllib.parse.urljoin(self.repo.remotes.origin.url + "/", self.url)
                        else:
                            url = self.url
                        mrepo = self._clone_repo(
                            self.repo,
                            url,
                            self.path,
                            self.name,
                            n=True,
                            env=env,
                            multi_options=clone_multi_options,
                            allow_unsafe_options=allow_unsafe_options,
                            allow_unsafe_protocols=allow_unsafe_protocols,
                        )
                    progress.update(END | CLONE, 0, 1, prefix + "Done cloning to %s" % checkout_module_abspath)

                    if not dry_run:
                        # See whether we have a valid branch to check out.
                        try:
                            mrepo = cast("Repo", mrepo)
                            remote_branch = find_first_remote_branch(mrepo.remotes, self.branch_name)
                            local_branch = mkhead(mrepo, self.branch_path)
                            local_branch.set_object(Object(mrepo, self.NULL_BIN_SHA))
                            mrepo.head.set_reference(
                                local_branch,
                                logmsg="submodule: attaching head to %s" % local_branch,
                            )
                            mrepo.head.reference.set_tracking_branch(remote_branch)
                        except (IndexError, InvalidGitRepositoryError):
                            _logger.warning("Failed to checkout tracking branch %s", self.branch_path)

                        with self.repo.config_writer() as writer:
                            writer.set_value(sm_section(self.name), "url", self.url)
            # END handle initialization

            # DETERMINE SHAS TO CHECK OUT
            #############################
            binsha = self.binsha
            hexsha = self.hexsha
            if mrepo is not None:
                # mrepo is only set if we are not in dry-run mode or if the module
                # existed.
                is_detached = mrepo.head.is_detached
            # END handle dry_run

            if mrepo is not None and to_latest_revision:
                msg_base = "Cannot update to latest revision in repository at %r as " % mrepo.working_dir
                if not is_detached:
                    rref = mrepo.head.reference.tracking_branch()
                    if rref is not None:
                        rcommit = rref.commit
                        binsha = rcommit.binsha
                        hexsha = rcommit.hexsha
                    else:
                        _logger.error(
                            "%s a tracking branch was not set for local branch '%s'",
                            msg_base,
                            mrepo.head.reference,
                        )
                    # END handle remote ref
                else:
                    _logger.error("%s there was no local tracking branch", msg_base)
                # END handle detached head
            # END handle to_latest_revision option

            # Update the working tree.
            # Handles dry_run.
            if mrepo is not None and mrepo.head.commit.binsha != binsha:
                # We must ensure that our destination sha (the one to point to) is in
                # the future of our current head. Otherwise, we will reset changes that
                # might have been done on the submodule, but were not yet pushed. We
                # also handle the case that history has been rewritten, leaving no
                # merge-base. In that case we behave conservatively, protecting possible
                # changes the user had done.
                may_reset = True
                if mrepo.head.commit.binsha != self.NULL_BIN_SHA:
                    base_commit = mrepo.merge_base(mrepo.head.commit, hexsha)
                    if len(base_commit) == 0 or (base_commit[0] is not None and base_commit[0].hexsha == hexsha):
                        if force:
                            msg = "Will force checkout or reset on local branch that is possibly in the future of"
                            msg += " the commit it will be checked out to, effectively 'forgetting' new commits"
                            _logger.debug(msg)
                        else:
                            msg = "Skipping %s on branch '%s' of submodule repo '%s' as it contains un-pushed commits"
                            msg %= (
                                is_detached and "checkout" or "reset",
                                mrepo.head,
                                mrepo,
                            )
                            _logger.info(msg)
                            may_reset = False
                        # END handle force
                    # END handle if we are in the future

                    if may_reset and not force and mrepo.is_dirty(index=True, working_tree=True, untracked_files=True):
                        raise RepositoryDirtyError(mrepo, "Cannot reset a dirty repository")
                    # END handle force and dirty state
                # END handle empty repo

                # END verify future/past
                progress.update(
                    BEGIN | UPDWKTREE,
                    0,
                    1,
                    prefix
                    + "Updating working tree at %s for submodule %r to revision %s" % (self.path, self.name, hexsha),
                )

                if not dry_run and may_reset:
                    if is_detached:
                        # NOTE: For now we force. The user is not supposed to change
                        # detached submodules anyway. Maybe at some point this becomes
                        # an option, to properly handle user modifications - see below
                        # for future options regarding rebase and merge.
                        mrepo.git.checkout(hexsha, force=force)
                    else:
                        mrepo.head.reset(hexsha, index=True, working_tree=True)
                    # END handle checkout
                # If we may reset/checkout.
                progress.update(
                    END | UPDWKTREE,
                    0,
                    1,
                    prefix + "Done updating working tree for submodule %r" % self.name,
                )
            # END update to new commit only if needed
        except Exception as err:
            if not keep_going:
                raise
            _logger.error(str(err))
        # END handle keep_going

        # HANDLE RECURSION
        ##################
        if recursive:
            # In dry_run mode, the module might not exist.
            if mrepo is not None:
                for submodule in self.iter_items(self.module()):
                    submodule.update(
                        recursive,
                        init,
                        to_latest_revision,
                        progress=progress,
                        dry_run=dry_run,
                        force=force,
                        keep_going=keep_going,
                    )
                # END handle recursive update
            # END handle dry run
        # END for each submodule

        return self

    @property
    def name(self) -> str:
        """
        :return:
            The name of this submodule. It is used to identify it within the
            ``.gitmodules`` file.

        :note:
            By default, this is the name is the path at which to find the submodule, but
            in GitPython it should be a unique identifier similar to the identifiers
            used for remotes, which allows to change the path of the submodule easily.
        """
        return self._name

    @classmethod
    def iter_items(
        cls,
        repo: "Repo",
        parent_commit: Union[Commit_ish, str] = "HEAD",
        *args: Any,
        **kwargs: Any,
    ) -> Iterator["Submodule"]:
        """
        :return:
            Iterator yielding :class:`Submodule` instances available in the given
            repository
        """
        try:
            pc = repo.commit(parent_commit)  # Parent commit instance
            parser = cls._config_parser(repo, pc, read_only=True)
        except (IOError, BadName):
            return
        # END handle empty iterator

        for sms in parser.sections():
            n = sm_name(sms)
            p = parser.get(sms, "path")
            u = parser.get(sms, "url")
            b = cls.k_head_default
            if parser.has_option(sms, cls.k_head_option):
                b = str(parser.get(sms, cls.k_head_option))
            # END handle optional information

            # Get the binsha.
            index = repo.index
            try:
                rt = pc.tree  # Root tree
                sm = rt[p]
            except KeyError:
                # Try the index, maybe it was just added.
                try:
                    entry = index.entries[index.entry_key(p, 0)]
                    sm = Submodule(repo, entry.binsha, entry.mode, entry.path)
                except KeyError:
                    # The submodule doesn't exist, probably it wasn't removed from the
                    # .gitmodules file.
                    continue
                # END handle keyerror
            # END handle critical error

            # Make sure we are looking at a submodule object.
            if type(sm) is not git.objects.submodule.base.Submodule:
                continue

            # Fill in remaining info - saves time as it doesn't have to be parsed again.
            sm._name = n
            if pc != repo.commit():
                sm._parent_commit = pc
            # END set only if not most recent!
            sm._branch_path = git.Head.to_full_path(b)
            sm._url = u

            yield sm
        # END for each section
