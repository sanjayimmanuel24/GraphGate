######
# Project       : lollms
# File          : binding.py
# Author        : ParisNeo with the help of the community
# license       : Apache 2.0
# Description   : 
# This is an interface class for lollms bindings.
######
from fastapi import Request
from typing import Dict, Any
from pathlib import Path
from typing import Callable
from lollms.paths import LollmsPaths
from ascii_colors import ASCIIColors
from urllib import request

import tempfile
import requests
import shutil
import os
import yaml
import importlib
import subprocess
from lollms.config import TypedConfig, InstallOption
from lollms.main_config import LOLLMSConfig
from lollms.com import NotificationType, NotificationDisplayType, LoLLMsCom
from lollms.security import sanitize_path
from lollms.utilities import show_message_dialog

import urllib
import inspect
from datetime import datetime
from enum import Enum
from lollms.utilities import trace_exception

from tqdm import tqdm
from lollms.databases.models_database import ModelsDB
import sys


class BindingBuilder:
    def build_binding(
                        self, 
                        config: LOLLMSConfig, 
                        lollms_paths:LollmsPaths,
                        installation_option:InstallOption=InstallOption.INSTALL_IF_NECESSARY,
                        lollmsCom=None
                    )->LLMBinding:

        binding:LLMBinding = self.getBinding(config, lollms_paths)
        return binding(
                config,
                lollms_paths=lollms_paths,
                installation_option = installation_option,
                lollmsCom=lollmsCom
                )

    def getBinding(
                        self, 
                        config: LOLLMSConfig, 
                        lollms_paths:LollmsPaths,
                    )->LLMBinding:
        
        if len(str(config.binding_name).split("/"))>1:
            binding_path = Path(config.binding_name)
        else:
            binding_path = lollms_paths.bindings_zoo_path / config["binding_name"]

        # define the full absolute path to the module
        absolute_path = binding_path.resolve()
        # infer the module name from the file path
        module_name = binding_path.stem
        # use importlib to load the module from the file path
        loader = importlib.machinery.SourceFileLoader(module_name, str(absolute_path / "__init__.py"))
        binding_module = loader.load_module()
        binding:LLMBinding = getattr(binding_module, binding_module.binding_name)
        return binding
