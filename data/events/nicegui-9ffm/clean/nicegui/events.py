from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, TypeVar, cast

from . import background_tasks, core, helpers
from .awaitable_response import AwaitableResponse
from .dataclasses import KWONLY_SLOTS
from .slot import Slot

if TYPE_CHECKING:
    from .client import Client
    from .element import Element
    from .elements.slide_item import SlideSide
    from .elements.upload_files import FileUpload
    from .observables import ObservableCollection


@dataclass(**KWONLY_SLOTS)
class EventArguments:
    pass


@dataclass(**KWONLY_SLOTS)
class UiEventArguments(EventArguments):
    sender: Element
    client: Client


@dataclass(**KWONLY_SLOTS)
class UploadEventArguments(UiEventArguments):
    file: FileUpload


@dataclass(**KWONLY_SLOTS)
class MultiUploadEventArguments(UiEventArguments):
    files: list[FileUpload]

EventT = TypeVar('EventT', bound=EventArguments)
Handler: TypeAlias = Callable[[EventT], Any] | Callable[[], Any]


def handle_event(handler: Handler[EventT] | None, arguments: EventT) -> None:
    """Call the given event handler.

    The handler is called within the context of the parent slot of the sender.
    If the handler is a coroutine, it is scheduled as a background task.
    If the handler expects arguments, the arguments are passed to the handler.
    Exceptions are caught and handled globally.

    :param handler: the event handler
    :param arguments: the event arguments
    """
    if handler is None:
        return
    try:
        parent_slot: Slot | nullcontext
        if isinstance(arguments, UiEventArguments):
            parent_slot = arguments.sender.parent_slot or arguments.sender.client.layout.default_slot
        else:
            parent_slot = nullcontext()

        with parent_slot:
            if helpers.expects_arguments(handler):
                result = cast(Callable[[EventT], Any], handler)(arguments)
            else:
                result = cast(Callable[[], Any], handler)()
        if isinstance(result, Awaitable) and not isinstance(result, AwaitableResponse) and not isinstance(result, asyncio.Task):
            # NOTE: await an awaitable result even if the handler is not a coroutine (like a lambda statement)
            async def wait_for_result():
                with parent_slot:
                    try:
                        await result
                    except Exception as e:
                        core.app.handle_exception(e)
            if core.loop and core.loop.is_running():
                background_tasks.create(wait_for_result(), name=str(handler))
            else:
                core.app.on_startup(wait_for_result())
    except Exception as e:
        core.app.handle_exception(e)
