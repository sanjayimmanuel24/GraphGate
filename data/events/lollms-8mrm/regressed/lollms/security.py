from fastapi import HTTPException
from ascii_colors import ASCIIColors
from urllib.parse import urlparse
import socket
from pathlib import Path
from typing import List
import os
import re
import platform
import string
from lollms.utilities import PackageManager

import lxml.etree as ET


def sanitize_path(path: str, allow_absolute_path: bool = False, error_text="Absolute database path detected", exception_text="Detected an attempt of path traversal or command injection. Are you kidding me?"):
    """
    Sanitize a given file path by checking for potentially dangerous patterns and unauthorized characters.

    Returns:
    -------
    str: The sanitized file path.
    """    
    if path is None:
        return path

    # Normalize path to use forward slashes
    path = path.replace('\\', '/')

    if not allow_absolute_path and path.strip().startswith("/"):
        raise HTTPException(status_code=400, detail=exception_text)

    suspicious_patterns = re.compile(r'(\.\.+)|(/+/)|(\$\(.*\))')

    if suspicious_patterns.search(str(path)) or ((not allow_absolute_path) and Path(path).is_absolute()):
        ASCIIColors.error(error_text)
        raise HTTPException(status_code=400, detail=exception_text)

    # Detect if any unauthorized characters, excluding the dot character, are present in the path
    unauthorized_chars = set('!"#$%&\'()*+,;<=>?@[]^`{|}~')
    if any(char in unauthorized_chars for char in path):
        raise HTTPException(status_code=400, detail=exception_text)

    if not allow_absolute_path:
        path = path.lstrip('/')

    return path
