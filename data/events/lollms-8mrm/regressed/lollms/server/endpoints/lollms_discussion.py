"""
project: lollms_webui
file: lollms_discussion.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes allow users to manipulate the discussion elements.

"""
from fastapi import APIRouter, Request
from lollms_webui import LOLLMSWebUI
from pydantic import BaseModel
from starlette.responses import StreamingResponse
from lollms.types import MSG_TYPE
from lollms.utilities import detect_antiprompt, remove_text_from_string, trace_exception
from lollms.security import sanitize_path, check_access
from ascii_colors import ASCIIColors
from lollms.databases.discussions_database import DiscussionsDB, Discussion
from typing import List
import shutil
from safe_store.text_vectorizer import TextVectorizer, VectorizationMethod, VisualizationMethod
import tqdm
from pathlib import Path

router = APIRouter()
lollmsElfServer:LOLLMSWebUI = LOLLMSWebUI.get_instance()


class DiscussionDelete(BaseModel):
    client_id: str
    id: int


@router.post("/delete_discussion")
async def delete_discussion(discussion: DiscussionDelete):
    """
    Executes Python code and returns the output.

    :param request: The HTTP request object.
    :return: A JSON response with the status of the operation.
    """
    check_access(lollmsElfServer, discussion.client_id)

    try:

        client_id           = discussion.client_id
        discussion_id       = discussion.id
        discussion_path = lollmsElfServer.lollms_paths.personal_discussions_path/lollmsElfServer.config.discussion_db_name/f"{discussion_id}"


        lollmsElfServer.session.get_client(client_id).discussion = Discussion(lollmsElfServer, discussion_id, lollmsElfServer.db)
        lollmsElfServer.session.get_client(client_id).discussion.delete_discussion()
        lollmsElfServer.session.get_client(client_id).discussion = None

        shutil.rmtree(discussion_path)
        return {'status':True}
    except Exception as ex:
        trace_exception(ex)
        lollmsElfServer.error(ex)
        return {"status":False,"error":str(ex)}
