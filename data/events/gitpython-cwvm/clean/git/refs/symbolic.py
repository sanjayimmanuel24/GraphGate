from git.types import PathLike
import os

from git.compat import defenc
from git.objects import Object
from git.objects.commit import Commit
from git.util import (
    join_path,
    join_path_native,
    to_native_path_linux,
    assure_directory_exists,
    hex_to_bin,
    LockedFD,
)
from gitdb.exc import BadObject, BadName

from .log import RefLog

from typing import (
    Any,
    Iterator,
    List,
    Tuple,
    Type,
    TypeVar,
    Union,
    TYPE_CHECKING,
    cast,
)  # NOQA
from git.types import Commit_ish, PathLike  # NOQA

if TYPE_CHECKING:
    from git.repo import Repo
    from git.refs import Head, TagReference, RemoteReference, Reference
    from .log import RefLogEntry
    from git.config import GitConfigParser
    from git.objects.commit import Actor


def _git_dir(repo: "Repo", path: Union[PathLike, None]) -> PathLike:
    """Find the git dir that's appropriate for the path"""
    name = f"{path}"
    if name in ["HEAD", "ORIG_HEAD", "FETCH_HEAD", "index", "logs"]:
        return repo.git_dir
    return repo.common_dir


class SymbolicReference(object):

    """Represents a special case of a reference such that this reference is symbolic.
    It does not point to a specific commit, but to another Head, which itself
    specifies a commit.

    A typical example for a symbolic reference is HEAD."""

    __slots__ = ("repo", "path")
    _resolve_ref_on_create = False
    _points_to_commits_only = True
    _common_path_default = ""
    _remote_common_path_default = "refs/remotes"
    _id_attribute_ = "name"

    def __init__(self, repo: "Repo", path: PathLike, check_path: bool = False):
        self.repo = repo
        self.path = path

    @classmethod
    def _get_packed_refs_path(cls, repo: "Repo") -> str:
        return os.path.join(repo.common_dir, "packed-refs")

    @classmethod
    def _iter_packed_refs(cls, repo: "Repo") -> Iterator[Tuple[str, str]]:
        """Returns an iterator yielding pairs of sha1/path pairs (as strings) for the corresponding refs.
        :note: The packed refs file will be kept open as long as we iterate"""
        try:
            with open(cls._get_packed_refs_path(repo), "rt", encoding="UTF-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        # "# pack-refs with: peeled fully-peeled sorted"
                        # the git source code shows "peeled",
                        # "fully-peeled" and "sorted" as the keywords
                        # that can go on this line, as per comments in git file
                        # refs/packed-backend.c
                        # I looked at master on 2017-10-11,
                        # commit 111ef79afe, after tag v2.15.0-rc1
                        # from repo https://github.com/git/git.git
                        if line.startswith("# pack-refs with:") and "peeled" not in line:
                            raise TypeError("PackingType of packed-Refs not understood: %r" % line)
                        # END abort if we do not understand the packing scheme
                        continue
                    # END parse comment

                    # skip dereferenced tag object entries - previous line was actual
                    # tag reference for it
                    if line[0] == "^":
                        continue

                    yield cast(Tuple[str, str], tuple(line.split(" ", 1)))
                # END for each line
        except OSError:
            return None
        # END no packed-refs file handling
        # NOTE: Had try-finally block around here to close the fp,
        # but some python version wouldn't allow yields within that.
        # I believe files are closing themselves on destruction, so it is
        # alright.

    @classmethod
    def dereference_recursive(cls, repo: "Repo", ref_path: Union[PathLike, None]) -> str:
        """
        :return: hexsha stored in the reference at the given ref_path, recursively dereferencing all
            intermediate references as required
        :param repo: the repository containing the reference at ref_path"""

        while True:
            hexsha, ref_path = cls._get_ref_info(repo, ref_path)
            if hexsha is not None:
                return hexsha
        # END recursive dereferencing

    @staticmethod
    def _check_ref_name_valid(ref_path: PathLike) -> None:
        # Based on the rules described in https://git-scm.com/docs/git-check-ref-format/#_description
        previous: Union[str, None] = None
        one_before_previous: Union[str, None] = None
        for c in str(ref_path):
            if c in " ~^:?*[\\":
                raise ValueError(
                    f"Invalid reference '{ref_path}': references cannot contain spaces, tildes (~), carets (^),"
                    f" colons (:), question marks (?), asterisks (*), open brackets ([) or backslashes (\\)"
                )
            elif c == ".":
                if previous is None or previous == "/":
                    raise ValueError(
                        f"Invalid reference '{ref_path}': references cannot start with a period (.) or contain '/.'"
                    )
                elif previous == ".":
                    raise ValueError(f"Invalid reference '{ref_path}': references cannot contain '..'")
            elif c == "/":
                if previous == "/":
                    raise ValueError(f"Invalid reference '{ref_path}': references cannot contain '//'")
                elif previous is None:
                    raise ValueError(
                        f"Invalid reference '{ref_path}': references cannot start with forward slashes '/'"
                    )
            elif c == "{" and previous == "@":
                raise ValueError(f"Invalid reference '{ref_path}': references cannot contain '@{{'")
            elif ord(c) < 32 or ord(c) == 127:
                raise ValueError(f"Invalid reference '{ref_path}': references cannot contain ASCII control characters")

            one_before_previous = previous
            previous = c

        if previous == ".":
            raise ValueError(f"Invalid reference '{ref_path}': references cannot end with a period (.)")
        elif previous == "/":
            raise ValueError(f"Invalid reference '{ref_path}': references cannot end with a forward slash (/)")
        elif previous == "@" and one_before_previous is None:
            raise ValueError(f"Invalid reference '{ref_path}': references cannot be '@'")
        elif any([component.endswith(".lock") for component in str(ref_path).split("/")]):
            raise ValueError(
                f"Invalid reference '{ref_path}': references cannot have slash-separated components that end with"
                f" '.lock'"
            )

    @classmethod
    def _get_ref_info_helper(
        cls, repo: "Repo", ref_path: Union[PathLike, None]
    ) -> Union[Tuple[str, None], Tuple[None, str]]:
        """Return: (str(sha), str(target_ref_path)) if available, the sha the file at
        rela_path points to, or None. target_ref_path is the reference we
        point to, or None"""
        if ref_path:
            cls._check_ref_name_valid(ref_path)

        tokens: Union[None, List[str], Tuple[str, str]] = None
        repodir = _git_dir(repo, ref_path)
        try:
            with open(os.path.join(repodir, str(ref_path)), "rt", encoding="UTF-8") as fp:
                value = fp.read().rstrip()
            # Don't only split on spaces, but on whitespace, which allows to parse lines like
            # 60b64ef992065e2600bfef6187a97f92398a9144                branch 'master' of git-server:/path/to/repo
            tokens = value.split()
            assert len(tokens) != 0
        except OSError:
            # Probably we are just packed, find our entry in the packed refs file
            # NOTE: We are not a symbolic ref if we are in a packed file, as these
            # are excluded explicitly
            for sha, path in cls._iter_packed_refs(repo):
                if path != ref_path:
                    continue
                # sha will be used
                tokens = sha, path
                break
            # END for each packed ref
        # END handle packed refs
        if tokens is None:
            raise ValueError("Reference at %r does not exist" % ref_path)

        # is it a reference ?
        if tokens[0] == "ref:":
            return (None, tokens[1])

        # its a commit
        if repo.re_hexsha_only.match(tokens[0]):
            return (tokens[0], None)

        raise ValueError("Failed to parse reference information from %r" % ref_path)

    @classmethod
    def _get_ref_info(cls, repo: "Repo", ref_path: Union[PathLike, None]) -> Union[Tuple[str, None], Tuple[None, str]]:
        """Return: (str(sha), str(target_ref_path)) if available, the sha the file at
        rela_path points to, or None. target_ref_path is the reference we
        point to, or None"""
        return cls._get_ref_info_helper(repo, ref_path)

    commit = property(_get_commit, set_commit, doc="Query or set commits directly")  # type: ignore
    object = property(_get_object, set_object, doc="Return the object our ref currently refers to")  # type: ignore

    # aliased reference
    reference: Union["Head", "TagReference", "RemoteReference", "Reference"]
    reference = property(_get_reference, set_reference, doc="Returns the Reference we point to")  # type: ignore
    ref = reference
