import asyncio
import inspect
import os
import platform
import signal
import urllib
from collections.abc import Awaitable, Iterator
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Union

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse

from .. import background_tasks, core, helpers
from ..client import Client
from ..logging import log
from ..native import NativeConfig
from ..observables import ObservableSet
from ..server import Server
from ..staticfiles import CacheControlledStaticFiles
from ..storage import Storage
from .app_config import AppConfig
from .range_response import get_range_response


class App(FastAPI):
    from ..timer import Timer as timer  # pylint: disable=import-outside-toplevel

    def add_media_files(self, url_path: str, local_directory: Union[str, Path]) -> None:
        """Add directory of media files.

        To make a single file accessible via streaming, you can use `add_media_file()`.
        For small static files, you can use `add_static_files()` or `add_static_file()` instead.

        :param url_path: string that starts with a slash "/" and identifies the path at which the files should be served
        :param local_directory: local folder with files to serve as media content
        """
        @self.get(url_path.rstrip('/') + '/{filename:path}')  # NOTE: prevent double slashes in route pattern
        def read_item(request: Request, filename: str, nicegui_chunk_size: int = 8192) -> Response:
            local_dir = Path(local_directory).resolve()
            filepath = (local_dir / filename).resolve()
            if not filepath.is_relative_to(local_dir) or not filepath.is_file():
                raise HTTPException(status_code=404, detail='Not Found')
            return get_range_response(filepath, request, chunk_size=nicegui_chunk_size)
