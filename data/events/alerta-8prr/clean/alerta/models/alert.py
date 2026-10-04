import os
import platform
import sys
from datetime import datetime
from typing import Optional  # noqa
from typing import Any, Dict, List, Tuple, Union
from uuid import uuid4

from flask import current_app, g

from alerta.app import alarm_model, db
from alerta.database.base import Query
from alerta.models.enums import ChangeType
from alerta.models.history import History, RichHistory
from alerta.models.note import Note
from alerta.utils.format import DateTime
from alerta.utils.hooks import status_change_hook
from alerta.utils.response import absolute_url


class Alert:

    # get severity counts
    @staticmethod
    def get_counts_by_severity(query: Query = None) -> Dict[str, Any]:
        return db.get_counts_by_severity(query)

    # get status counts
    @staticmethod
    def get_counts_by_status(query: Query = None) -> Dict[str, Any]:
        return db.get_counts_by_status(query)
