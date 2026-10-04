import threading
import time
from collections import defaultdict, namedtuple
from datetime import datetime

import psycopg2
from flask import current_app
from psycopg2.extensions import AsIs, adapt, register_adapter
from psycopg2.extras import Json, NamedTupleCursor, register_composite

from alerta.app import alarm_model
from alerta.database.base import Database
from alerta.exceptions import NoCustomerMatch
from alerta.models.enums import ADMIN_SCOPES
from alerta.models.heartbeat import HeartbeatStatus
from alerta.utils.format import DateTime
from alerta.utils.response import absolute_url

from .utils import Query


class Backend(Database):

    def get_counts_by_severity(self, query=None):
        query = query or Query()
        select = f"""
            SELECT severity, COUNT(*) FROM alerts
             WHERE {query.where}
            GROUP BY severity
        """
        return {s.severity: s.count for s in self._fetchall(select, query.vars)}

    def get_counts_by_status(self, query=None):
        query = query or Query()
        select = f"""
            SELECT status, COUNT(*) FROM alerts
            WHERE {query.where}
            GROUP BY status
        """
        return {s.status: s.count for s in self._fetchall(select, query.vars)}

    def _fetchall(self, query, vars, limit=None, offset=0):
        """
        Return multiple rows.
        """
        if limit is None:
            limit = current_app.config['DEFAULT_PAGE_SIZE']
        query += f' LIMIT {limit} OFFSET {offset}'
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        return cursor.fetchall()

    def _log(self, cursor, query, vars):
        current_app.logger.debug('{stars}\n{query}\n{stars}'.format(
            stars='*' * 40, query=cursor.mogrify(query, vars).decode('utf-8')))
