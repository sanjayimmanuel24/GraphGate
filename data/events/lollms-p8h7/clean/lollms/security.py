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


def sanitize_path_from_endpoint(path: str, error_text: str = "A suspected LFI attack detected. The path sent to the server has suspicious elements in it!", exception_text: str = "Invalid path!") -> str:
    """
    Returns:
    -------
    str: The sanitized file path.
    """

    if path is None:
        return path

    # Normalize path to use forward slashes
    path = path.replace('\\', '/')

    if path.strip().startswith("/"):
        raise HTTPException(status_code=400, detail=exception_text)

    # Regular expression to detect patterns like "...." and multiple forward slashes
    suspicious_patterns = re.compile(r'(\.\.+)|(/+/)')

    # Detect if any unauthorized characters, excluding the dot character, are present in the path
    unauthorized_chars = set('!"#$%&\'()*+,:;<=>?@[]^`{|}~')
    if any(char in unauthorized_chars for char in path):
        raise HTTPException(status_code=400, detail=exception_text)

    if suspicious_patterns.search(path) or Path(path).is_absolute():
        raise HTTPException(status_code=400, detail=error_text)

    path = path.lstrip('/')
    return path
