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
from lollms.utilities import load_config, trace_exception, gc, PackageManager, run_async
from pathlib import Path
from typing import List, Optional, Dict
from lollms.security import check_access
from functools import partial
import os
import re
import threading
# ----------------------- Defining router and main class ------------------------------
router = APIRouter()
lollmsElfServer = LOLLMSElfServer.get_instance()


class FolderInfos(BaseModel):
    client_id: str
    db_path: str


@router.post("/vectorize_folder")
async def vectorize_folder(database_infos: FolderInfos):
    """
    Selects and names a database 
    """ 
    client = check_access(lollmsElfServer, database_infos.client_id)
    def process():
        if "::" in database_infos.db_path:
            parts = database_infos.db_path.split("::")
            db_name = parts[0]
            folder_path = parts[1]
        else:
            import tkinter as tk
            from tkinter import simpledialog, filedialog
            # Create a new Tkinter root window and hide it
            root = tk.Tk()
            root.withdraw()
            
            # Make the window appear on top
            root.attributes('-topmost', True)
            
            # Ask for the database name
            db_name = simpledialog.askstring("Database Name", "Please enter the database name:")
            folder_path = database_infos.db_path
                
            
        if db_name:
            try:
                lollmsElfServer.ShowBlockingMessage("Revectorizing the database.")
                if not PackageManager.check_package_installed_with_version("lollmsvectordb","0.6.0"):
                    PackageManager.install_or_update("lollmsvectordb")
                
                from lollmsvectordb.lollms_vectorizers.bert_vectorizer import BERTVectorizer
                from lollmsvectordb import VectorDatabase
                from lollmsvectordb.text_document_loader import TextDocumentsLoader
                from lollmsvectordb.lollms_tokenizers.tiktoken_tokenizer import TikTokenTokenizer


                if lollmsElfServer.config.rag_vectorizer == "bert":
                    lollmsElfServer.backup_trust_store()
                    from lollmsvectordb.lollms_vectorizers.bert_vectorizer import BERTVectorizer
                    v = BERTVectorizer()
                    lollmsElfServer.restore_trust_store()
                    
                elif lollmsElfServer.config.rag_vectorizer == "tfidf":
                    from lollmsvectordb.lollms_vectorizers.tfidf_vectorizer import TFIDFVectorizer
                    v = TFIDFVectorizer()
                vector_db_path = Path(folder_path)/f"{db_name}.sqlite"

                vdb = VectorDatabase(vector_db_path, v, lollmsElfServer.model if lollmsElfServer.model else TikTokenTokenizer(), reset=True)
                vdb.new_data = True
                # Get all files in the folder
                folder = Path(folder_path)
                file_types = [f"**/*{f}" if lollmsElfServer.config.rag_follow_subfolders else f"*{f}" for f in TextDocumentsLoader.get_supported_file_types()]
                files = []
                for file_type in file_types:
                    files.extend(folder.glob(file_type))
                
                # Load and add each document to the database
                for fn in files:
                    try:
                        text = TextDocumentsLoader.read_file(fn)
                        title = fn.stem  # Use the file name without extension as the title
                        lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nAdding {title}")
                        vdb.add_document(title, text, fn)
                        print(f"Added document: {title}")
                    except Exception as e:
                        lollmsElfServer.error(f"Failed to add document {fn}: {e}")
                if vdb.new_data: #New files are added, need reindexing
                    lollmsElfServer.ShowBlockingMessage(f"Adding a new database.\nIndexing the database...")
                    vdb.build_index()
                    ASCIIColors.success("OK")
                lollmsElfServer.HideBlockingMessage()
                run_async(partial(lollmsElfServer.sio.emit,'rag_db_added', {"database_name": db_name, "database_path": str(folder_path)}, to=client.client_id))

            except Exception as ex:
                trace_exception(ex)
                lollmsElfServer.HideBlockingMessage()
    lollmsElfServer.rag_thread = threading.Thread(target=process)
    lollmsElfServer.rag_thread.start()
