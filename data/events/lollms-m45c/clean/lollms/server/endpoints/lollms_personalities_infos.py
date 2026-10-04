"""
project: lollms
file: lollms_personalities_infos.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to handling personalities related operations.

"""
from fastapi import APIRouter, Request
from fastapi import HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from lollms.personality import AIPersonality, InstallOption
from ascii_colors import ASCIIColors
from lollms.utilities import load_config, trace_exception, gc, show_yes_no_dialog
from lollms.security import check_access, forbid_remote_access
from pathlib import Path
from typing import List, Optional
import psutil
import yaml
from lollms.security import sanitize_path

# ----------------------- Defining router and main class ------------------------------
router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()


class PersonalityConfig(BaseModel):
    client_id:str
    category:str
    name:str
    config:dict


@router.post("/set_personality_config")
def set_personality_config(data:PersonalityConfig):
    forbid_remote_access(lollmsElfServer)
    check_access(lollmsElfServer, data.client_id)
    print("- Recovering personality config")
    category = sanitize_path(data.category)
    name = sanitize_path(data.name)
    config = data.config
    if category=="":
        return {"status":False, "error":"category must not be empty."}
    
    package_path = f"{category}/{name}"
    if category=="custom_personalities":
        package_full_path = lollmsElfServer.lollms_paths.custom_personalities_path/f"{name}"
    else:            
        package_full_path = lollmsElfServer.lollms_paths.personalities_zoo_path/package_path
    
    config_file = package_full_path / "config.yaml"
    if config_file.exists():
        with open(config_file,"w") as f:
            yaml.safe_dump(config, f)

        lollmsElfServer.mounted_personalities = lollmsElfServer.rebuild_personalities(reload_all=True)
        lollmsElfServer.InfoMessage("Personality updated")
        return {"status":True}
    else:
        return {"status":False, "error":"Not found"}
