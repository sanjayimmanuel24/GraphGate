# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
Implementation of a DAV provider that serves resource from a file system.

:class:`~wsgidav.fs_dav_provider.FilesystemProvider` implements a DAV resource
provider that publishes a file system.

If ``readonly=True`` is passed, write attempts will raise HTTP_FORBIDDEN.

This provider creates instances of :class:`~wsgidav.fs_dav_provider.FileResource`
and :class:`~wsgidav.fs_dav_provider.FolderResource` to represent files and
directories respectively.
"""

import os
import shutil
import stat
import sys
from typing import List

from wsgidav import util
from wsgidav.dav_error import HTTP_FORBIDDEN, DAVError
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider

_logger = util.get_module_logger(__name__)

BUFFER_SIZE = 8192


# ========================================================================
# FileResource
# ========================================================================
class FileResource(DAVNonCollection):
    """Represents a single existing DAV resource instance.

    See also _DAVResource, DAVNonCollection, and FilesystemProvider.
    """

    def __init__(self, path: str, environ: dict, file_path: str):
        super().__init__(path, environ)
        self._file_path: str = file_path
        self.file_stat: os.stat_result = os.stat(self._file_path)
        # Setting the name from the file path should fix the case on Windows
        self.name: str = os.path.basename(self._file_path)
        self.name = util.to_str(self.name)

    def get_content(self):
        """Open content as a stream for reading.

        See DAVResource.get_content()
        """
        assert not self.is_collection
        # GC issue 28, 57: if we open in text mode, \r\n is converted to one byte.
        # So the file size reported by Windows differs from len(..), thus
        # content-length will be wrong.
        return open(self._file_path, "rb", BUFFER_SIZE)


# ========================================================================
# FilesystemProvider
# ========================================================================
class FilesystemProvider(DAVProvider):
    """Default implementation of a filesystem DAVProvider.

    Args:
        root_folder (str)
        readonly (bool)
        fs_opts (dict | None): defaults to `config.fs_dav_provider`
        shadow (dict):  @deprecated (Use option `fs_provider.shadow_map` instead)
    """

    def __init__(self, root_folder, *, readonly=False, fs_opts=None):
        # root_folder is typically already resolved relative to config file
        # and has user ~ expanded
        root_folder = os.path.abspath(root_folder)
        if not root_folder or not os.path.exists(root_folder):
            raise ValueError(f"Invalid root path: {root_folder}")

        super().__init__()

        self.root_folder_path = root_folder
        self.readonly = readonly
        if fs_opts is None:
            _logger.warning(f"{self}: no `fs_opts` parameter passed to constructor.")
            fs_opts = {}
        self.fs_opts = fs_opts
        # Get shadow map and convert keys to lower case
        self.shadow_map = self.fs_opts.get("shadow_map") or {}
        if self.shadow_map:
            self.shadow_map = {k.lower(): v for k, v in self.shadow_map.items()}

    def _resolve_shadow_path(self, path: str, environ: dict, file_path):
        """File not found: See if there is a shadow configured."""
        shadow = self.shadow_map.get(path.lower())
        # _logger.info(f"Shadow {path} -> {shadow} {self.shadow}")
        if not shadow:
            return False, file_path

        err = None
        method = environ["REQUEST_METHOD"].upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            err = f"Shadow {path} -> {shadow}: ignored for method {method!r}."
        elif os.path.exists(file_path):
            err = f"Shadow {path} -> {shadow}: ignored for existing resource {file_path!r}."
        elif not os.path.exists(shadow):
            err = f"Shadow {path} -> {shadow}: does not exist."

        if err:
            _logger.warning(err)
            return False, file_path
        _logger.info(f"Shadow {path} -> {shadow}")
        return True, shadow

    def _loc_to_file_path(self, path: str, environ: dict = None):
        """Convert resource path to a unicode absolute file path.
        Optional environ argument may be useful e.g. in relation to per-user
        sub-folder chrooting inside root_folder_path.
        """
        root_path = self.root_folder_path
        assert root_path is not None
        assert util.is_str(root_path)
        assert util.is_str(path)

        path_parts = path.strip("/").split("/")
        file_path = os.path.abspath(os.path.join(root_path, *path_parts))

        # Try alternative URL if not found (or even override target):
        is_shadow, file_path = self._resolve_shadow_path(path, environ, file_path)

        if not file_path.startswith(root_path) and not is_shadow:
            raise RuntimeError(
                f"Security exception: tried to access file outside root: {file_path}"
            )

        # Convert to unicode
        file_path = util.to_unicode_safe(file_path)
        return file_path

    def get_resource_inst(self, path: str, environ: dict) -> FileResource:
        """Return info dictionary for path.

        See DAVProvider.get_resource_inst()
        """
        self._count_get_resource_inst += 1
        fp = self._loc_to_file_path(path, environ)

        if not os.path.exists(fp):
            return None
        if not self.fs_opts.get("follow_symlinks") and os.path.islink(fp):
            raise DAVError(HTTP_FORBIDDEN, f"Symlink support is disabled: {fp!r}")
        if os.path.isdir(fp):
            return FolderResource(path, environ, fp)
        return FileResource(path, environ, fp)
