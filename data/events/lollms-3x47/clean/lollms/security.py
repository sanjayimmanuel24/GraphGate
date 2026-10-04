from fastapi import HTTPException
from ascii_colors import ASCIIColors
from urllib.parse import urlparse
import socket
from pathlib import Path
from typing import List
import os
import re
import platform


def sanitize_path_from_endpoint(path: str, error_text="A suspected LFI attack detected. The path sent to the server has suspicious elements in it!", exception_text="Invalid path!"):
    if path.strip().startswith("/"):
        raise HTTPException(status_code=400, detail=exception_text)
    # Fix the case of "/" at the beginning on the path
    if path is None:
        return path
    
    # Regular expression to detect patterns like "...." and multiple forward slashes
    suspicious_patterns = re.compile(r'(\.\.+)|(/+/)')
    
    if suspicious_patterns.search(path) or Path(path).is_absolute():
        ASCIIColors.error(error_text)
        raise HTTPException(status_code=400, detail=exception_text)
    
    path = path.lstrip('/')
    return path
