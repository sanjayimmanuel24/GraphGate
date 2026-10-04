from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, TypeVar, cast

from . import background_tasks, core, helpers
from .slot import Slot

if TYPE_CHECKING:
    from .client import Client
    from .element import Element
    from .elements.slide_item import SlideSide
    from .elements.upload_files import FileUpload
    from .observables import ObservableCollection


@dataclass(kw_only=True, slots=True)
class EventArguments:
    pass


@dataclass(kw_only=True, slots=True)
class UiEventArguments(EventArguments):
    sender: Element
    client: Client


@dataclass(kw_only=True, slots=True)
class UploadEventArguments(UiEventArguments):
    file: FileUpload

EventT = TypeVar('EventT', bound=EventArguments)
Handler: TypeAlias = Callable[[EventT], Any] | Callable[[], Any]


def handle_event(handler: Handler[EventT] | None, arguments: EventT) -> None:
    """Call the given event handler.

    The handler is called within the context of the parent slot of the sender.
    If the handler returns an awaitable, it is scheduled as a background task.
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
        if helpers.should_await(result):
            background_tasks.create_or_defer(helpers.await_with_context(result, parent_slot), name=str(handler))
    except Exception as e:
        core.app.handle_exception(e)
