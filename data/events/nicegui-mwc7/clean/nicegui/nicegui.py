import asyncio
import mimetypes
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict

import socketio
from fastapi import HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import air, background_tasks, binding, core, favicon, helpers, json, run, welcome
from .app import App
from .client import Client
from .dependencies import js_components, libraries, resources
from .error import error_content
from .json import NiceGUIJSONResponse
from .logging import log
from .middlewares import RedirectWithPrefixMiddleware
from .page import page
from .slot import Slot
from .version import __version__


@asynccontextmanager
async def _lifespan(_: App):
    await _startup()
    yield
    await _shutdown()

core.app = app = App(default_response_class=NiceGUIJSONResponse, lifespan=_lifespan)
# NOTE we use custom json module which wraps orjson
core.sio = sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*', json=json)

Client.auto_index_client = Client(page('/'), shared=True).__enter__()  # pylint: disable=unnecessary-dunder-call


@app.get(f'/_nicegui/{__version__}' + '/libraries/{key:path}')
def _get_library(key: str) -> FileResponse:
    is_map = key.endswith('.map')
    dict_key = key[:-4] if is_map else key
    if dict_key in libraries:
        path = libraries[dict_key].path
        if is_map:
            path = path.with_name(path.name + '.map')
        if path.exists():
            headers = {'Cache-Control': 'public, max-age=3600'}
            return FileResponse(path, media_type='text/javascript', headers=headers)
    raise HTTPException(status_code=404, detail=f'library "{key}" not found')


@app.get(f'/_nicegui/{__version__}' + '/components/{key:path}')
def _get_component(key: str) -> FileResponse:
    if key in js_components and js_components[key].path.exists():
        headers = {'Cache-Control': 'public, max-age=3600'}
        return FileResponse(js_components[key].path, media_type='text/javascript', headers=headers)
    raise HTTPException(status_code=404, detail=f'component "{key}" not found')


@app.get(f'/_nicegui/{__version__}' + '/resources/{key}/{path:path}')
def _get_resource(key: str, path: str) -> FileResponse:
    if key in resources:
        filepath = resources[key].path / path
        try:
            filepath.resolve().relative_to(resources[key].path.resolve())  # NOTE: use is_relative_to() in Python 3.9
        except ValueError as e:
            raise HTTPException(status_code=403, detail='forbidden') from e
        if filepath.exists():
            headers = {'Cache-Control': 'public, max-age=3600'}
            media_type, _ = mimetypes.guess_type(filepath)
            return FileResponse(filepath, media_type=media_type, headers=headers)
    raise HTTPException(status_code=404, detail=f'resource "{key}" not found')


async def _startup() -> None:
    """Handle the startup event."""
    if not app.config.has_run_config:
        raise RuntimeError('\n\n'
                           'You must call ui.run() to start the server.\n'
                           'If ui.run() is behind a main guard\n'
                           '   if __name__ == "__main__":\n'
                           'remove the guard or replace it with\n'
                           '   if __name__ in {"__main__", "__mp_main__"}:\n'
                           'to allow for multiprocessing.')
    await welcome.collect_urls()
    # NOTE ping interval and timeout need to be lower than the reconnect timeout, but can't be too low
    sio.eio.ping_interval = max(app.config.reconnect_timeout * 0.8, 4)
    sio.eio.ping_timeout = max(app.config.reconnect_timeout * 0.4, 2)
    if core.app.config.favicon:
        if helpers.is_file(core.app.config.favicon):
            app.add_route('/favicon.ico', lambda _: FileResponse(core.app.config.favicon))  # type: ignore
        else:
            app.add_route('/favicon.ico', lambda _: favicon.get_favicon_response())
    else:
        app.add_route('/favicon.ico', lambda _: FileResponse(Path(__file__).parent / 'static' / 'favicon.ico'))
    core.loop = asyncio.get_running_loop()
    app.start()
    background_tasks.create(binding.refresh_loop(), name='refresh bindings')
    background_tasks.create(Client.prune_instances(), name='prune clients')
    background_tasks.create(Slot.prune_stacks(), name='prune slot stacks')
    background_tasks.create(core.app.storage.prune_tab_storage(), name='prune tab storage')
    air.connect()


async def _shutdown() -> None:
    """Handle the shutdown event."""
    if app.native.main_window:
        app.native.main_window.signal_server_shutdown()
    air.disconnect()
    app.stop()
    run.tear_down()
