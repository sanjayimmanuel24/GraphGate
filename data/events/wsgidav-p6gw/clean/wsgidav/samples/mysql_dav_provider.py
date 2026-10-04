# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
"""
Implementation of a WebDAV provider that provides a very basic, read-only
resource layer emulation of a MySQL database.

This module is specific to the WsgiDAV application. It provides a
classes ``MySQLBrowserProvider``.

Usage::

    (see docs/sample_wsgidav.yaml)
    MySQLBrowserProvider(host, user, passwd, db)

    host - host of database server
    user - user_name to access database
    passwd - passwd to access database
    db - name of database on database server

The ``MySQLBrowserProvider`` provides a very basic, read-only
resource layer emulation of a MySQL database.
It provides the following interface:

    - the root collection shared consists of collections that correspond to
      table names

    - in each table collection, there is a resource called "_ENTIRE_CONTENTS".
      This is a non-collection resource that returns a csv representation of the
      entire table

    - if the table has a single primary key, each table record will also appear
      as a non-collection resource in the table collection using the primary key
      value as its name. This resource returns a csv representation of the record
      and will also include the record attributes as live properties with
      attribute name as property name and table name suffixed with colon as the
      property namespace


This is a very basic interface and below is a by no means thorough summary of
its limitations:

    - Really only supports having numbers or strings as primary keys. The code uses
      a numeric or string comparison that may not hold up if the primary key is
      a date or some other datatype.

    - There is no handling for cases like BLOBs as primary keys or such. Well, there is
      no handling for BLOBs in general.

    - When returning contents, it buffers the entire contents! A bad way to return
      large tables. Ideally you would have a FileMixin that reads the database even
      as the application reads the file object....

    - It takes too many database queries to return information.
      Ideally there should be some sort of caching for metadata at least, to avoid
      unnecessary queries to the database.

"""

import csv
import hashlib
import time
from io import StringIO

import MySQLdb  # @UnresolvedImport

from wsgidav import util
from wsgidav.dav_error import (
    HTTP_FORBIDDEN,
    DAVError,
    PRECONDITION_CODE_ProtectedProperty,
)
from wsgidav.dav_provider import DAVProvider, _DAVResource


def _escape_id(identifier):
    """Escape MySQL identifier (table, column, database name)."""
    return identifier.replace("`", "``")


class MySQLBrowserProvider(DAVProvider):
    def __init__(self, host, user, passwd, db):
        super().__init__()
        self._host = host
        self._user = user
        self._passwd = passwd
        self._db = db
        self._count_initConnection = 0

    def _split_path(self, path):
        """Return (tableName, primaryKey) tuple for a request path."""
        if path.strip() in (None, "", "/"):
            return (None, None)
        tableName, primKey = util.save_split(path.strip("/"), "/", 1)
        #        _logger.debug("'%s' -> ('%s', '%s')" % (path, tableName, primKey))
        return (tableName, primKey)

    def _init_connection(self):
        self._count_initConnection += 1
        return MySQLdb.connect(
            host=self._host, user=self._user, passwd=self._passwd, db=self._db
        )

    def _is_data_type_numeric(self, datatype):
        if datatype is None:
            return False
        # how many MySQL datatypes does it take to change a lig... I mean, store numbers
        numerictypes = [
            "BIGINT",
            "INTT",
            "MEDIUMINT",
            "SMALLINT",
            "TINYINT",
            "BIT",
            "DEC",
            "DECIMAL",
            "DOUBLE",
            "FLOAT",
            "REAL",
            "DOUBLE PRECISION",
            "INTEGER",
            "NUMERIC",
        ]
        datatype = datatype.upper()
        for numtype in numerictypes:
            if datatype.startswith(numtype):
                return True
        return False

    def _exists_record_by_primary_key(self, conn, table_name, pri_key_value):
        pri_key = None
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("DESCRIBE `%s`" % _escape_id(table_name))
        result_set = cursor.fetchall()
        for row in result_set:
            if row["Key"] == "PRI":
                if pri_key is None:
                    pri_key = row["Field"]
                else:
                    return False  # more than one primary key - multipart key?
        cursor.close()

        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        sql = (
            "SELECT `{pri_key}` FROM `{db}`.`{table}` WHERE `{pri_key}` = %s"
        ).format(
            pri_key=_escape_id(pri_key),
            db=_escape_id(self._db),
            table=_escape_id(table_name),
        )
        cursor.execute(sql, (pri_key_value,))
        row = cursor.fetchone()
        if row is None:
            cursor.close()
            return False
        cursor.close()
        return True

    def _list_tables(self, conn):
        retlist = []
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        result_set = cursor.fetchall()
        for row in result_set:
            retlist.append("%s" % (row[0]))
        cursor.close()
        return retlist

    def get_resource_inst(self, path, environ):
        """Return info dictionary for path.

        See get_resource_inst()
        """
        # TODO: calling exists() makes directory browsing VERY slow.
        #       At least compared to PyFileServer, which simply used string
        #       functions to get display_type and displayTypeComment
        self._count_get_resource_inst += 1
        if not self.exists(path, environ):
            return None
        _tableName, primKey = self._split_path(path)
        is_collection = primKey is None
        return MySQLBrowserResource(self, path, is_collection, environ)

    def exists(self, path, environ):
        tableName, primKey = self._split_path(path)
        if tableName is None:
            return True

        try:
            conn = None
            conn = self._init_connection()
            # Check table existence:
            tbllist = self._list_tables(conn)
            if tableName not in tbllist:
                return False
            # Check table key existence:
            if primKey and primKey != "_ENTIRE_CONTENTS":
                return self._exists_record_by_primary_key(conn, tableName, primKey)
            return True
        finally:
            if conn:
                conn.close()
