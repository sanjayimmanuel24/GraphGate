"""
project: lollms
file: lollms_binding_files_server.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to serving files

"""
from fastapi import APIRouter, Request, Depends
from fastapi import HTTPException
from pydantic import BaseModel, validator
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from fastapi.responses import FileResponse
from lollms.binding import BindingBuilder, InstallOption
from lollms.security import sanitize_path_from_endpoint
from ascii_colors import ASCIIColors
from lollms.utilities import load_config, trace_exception, gc
from pathlib import Path
from typing import List
import os
import re

# ----------------------- Defining router and main class ------------------------------
router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()


# ----------------------------------- Personal files -----------------------------------------
@router.get("/user_infos/{path:path}")
async def serve_user_infos(path: str):
    """
    Serve user information file.

    Args:
        path (FilePath): The validated path to the file to be served.

    Returns:
        FileResponse: The file response containing the requested file.
    """ 
    path = sanitize_path_from_endpoint(path)

    file_path:Path = lollmsElfServer.lollms_paths.personal_user_infos_path / path
    if not file_path.exists():
        raise HTTPException(status_code=400, detail="File not found")
    return FileResponse(str(file_path))
