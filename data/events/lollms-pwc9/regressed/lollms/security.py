from fastapi import HTTPException
from ascii_colors import ASCIIColors
from pathlib import Path
from typing import List
import os


def sanitize_path(path:str, allow_absolute_path:bool=False, error_text="Absolute database path detected", exception_text="Detected an attempt of path traversal. Are you kidding me?"):
    if path is None:
        return path
    if(".." in path):
        ASCIIColors.warning(error_text)
        raise exception_text
    if (not allow_absolute_path) and Path(path).is_absolute():
        ASCIIColors.warning(error_text)
        raise exception_text
    return path
