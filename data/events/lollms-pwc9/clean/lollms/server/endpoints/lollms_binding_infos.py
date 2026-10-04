"""
project: lollms
file: lollms_binding_infos.py 
author: ParisNeo
description: 
    This module contains a set of FastAPI routes that provide information about the Lord of Large Language and Multimodal Systems (LoLLMs) Web UI
    application. These routes are specific to bindings

"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
import pkg_resources
from lollms.server.elf_server import LOLLMSElfServer
from lollms.binding import BindingBuilder, InstallOption
from ascii_colors import ASCIIColors
from lollms.utilities import load_config, trace_exception, gc
from lollms.security import sanitize_path_from_endpoint, sanitize_path
from pathlib import Path
from typing import List, Any
import json
import os


class BindingInstallParams(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)

# ----------------------- Defining router and main class ------------------------------
router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()


@router.post("/reinstall_binding")
def reinstall_binding(data:BindingInstallParams):
    """Reinstall an already installed binding on the server.
    
    Args:
        data (BindingInstallParams): Parameters required for reinstallation.
        format:
            name: str : the name of the binding
    
    Returns:
        dict: Status of operation.
    """    
    ASCIIColors.info(f"- Reinstalling binding {data.name}...")
    try:
        ASCIIColors.info("Unmounting binding and model")
        del lollmsElfServer.binding
        lollmsElfServer.binding = None
        gc.collect()
        ASCIIColors.info("Reinstalling binding")
        old_bn = lollmsElfServer.config.binding_name
        lollmsElfServer.config.binding_name = sanitize_path(data.name)
        lollmsElfServer.binding =  BindingBuilder().build_binding(lollmsElfServer.config, lollmsElfServer.lollms_paths, InstallOption.FORCE_INSTALL, lollmsCom=lollmsElfServer)
        lollmsElfServer.success("Binding reinstalled successfully")
        lollmsElfServer.config.binding_name = old_bn
        lollmsElfServer.binding =  BindingBuilder().build_binding(lollmsElfServer.config, lollmsElfServer.lollms_paths, lollmsCom=lollmsElfServer)
        lollmsElfServer.model = lollmsElfServer.binding.build_model()
        for per in lollmsElfServer.mounted_personalities:
            if per is not None:
                per.model = lollmsElfServer.model
        
        return {"status": True}
    except Exception as ex:
        ASCIIColors.error(f"Couldn't build binding: [{ex}]")
        trace_exception(ex)
        return {"status":False, 'error':str(ex)}


@router.post("/unInstall_binding")
def unInstall_binding(data:BindingInstallParams):
    """Uninstall an installed binding from the server.
    
    Args:
        data (BindingInstallParams): Parameters required for uninstallation.
        format:
            name: str : the name of the binding
    Returns:
        dict: Status of operation.
    """    
    ASCIIColors.info(f"- Reinstalling binding {data.name}...")
    try:
        ASCIIColors.info("Unmounting binding and model")
        if lollmsElfServer.binding is not None:
            del lollmsElfServer.binding
            lollmsElfServer.binding = None
            gc.collect()
        ASCIIColors.info("Uninstalling binding")
        old_bn = lollmsElfServer.config.binding_name
        lollmsElfServer.config.binding_name = sanitize_path(data.name)
        lollmsElfServer.binding =  BindingBuilder().build_binding(lollmsElfServer.config, lollmsElfServer.lollms_paths, InstallOption.NEVER_INSTALL, lollmsCom=lollmsElfServer)
        lollmsElfServer.binding.uninstall()
        ASCIIColors.green("Uninstalled successful")
        if old_bn!=lollmsElfServer.config.binding_name:
            lollmsElfServer.config.binding_name = old_bn
            lollmsElfServer.binding =  BindingBuilder().build_binding(lollmsElfServer.config, lollmsElfServer.lollms_paths, lollmsCom=lollmsElfServer)
            lollmsElfServer.model = lollmsElfServer.binding.build_model()
            for per in lollmsElfServer.mounted_personalities:
                if per is not None:
                    per.model = lollmsElfServer.model
        else:
            lollmsElfServer.config.binding_name = None
        if lollmsElfServer.config.auto_save:
            ASCIIColors.info("Saving configuration")
            lollmsElfServer.config.save_config()
            
        return {"status": True}
    except Exception as ex:
        ASCIIColors.error(f"Couldn't build binding: [{ex}]")
        trace_exception(ex)
        return {"status":False, 'error':str(ex)}     
