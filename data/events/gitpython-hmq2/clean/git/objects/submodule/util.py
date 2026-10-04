from io import BytesIO
import weakref

import git
from git.config import GitConfigParser
from git.exc import InvalidGitRepositoryError

from typing import Any, Sequence, TYPE_CHECKING, Union

from git.types import PathLike

if TYPE_CHECKING:
    from weakref import ReferenceType

    from git.refs import Head, RemoteReference
    from git.remote import Remote
    from git.repo import Repo

    from .base import Submodule


def sm_name(section: str) -> str:
    """:return: Name of the submodule as parsed from the section name"""
    section = section.strip()
    return section[11:-1]
