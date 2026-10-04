import asyncio
from functools import wraps
from typing import Any, Callable, List, Optional, SupportsInt, Tuple, TypeVar, Union

import aiomysql
import pymysql
from pymysql.charset import charset_by_name
from pypika import MySQLQuery

from tortoise.backends.base.client import (
    BaseDBAsyncClient,
    BaseTransactionWrapper,
    Capabilities,
    ConnectionWrapper,
    NestedTransactionPooledContext,
    PoolConnectionWrapper,
    TransactionContext,
    TransactionContextPooled,
)
from tortoise.backends.mysql.executor import MySQLExecutor
from tortoise.backends.mysql.schema_generator import MySQLSchemaGenerator
from tortoise.exceptions import (
    DBConnectionError,
    IntegrityError,
    OperationalError,
    TransactionManagementError,
)

FuncType = Callable[..., Any]
F = TypeVar("F", bound=FuncType)


def translate_exceptions(func: F) -> F:
    @wraps(func)
    async def translate_exceptions_(self, *args):
        try:
            return await func(self, *args)
        except (
            pymysql.err.OperationalError,
            pymysql.err.ProgrammingError,
            pymysql.err.DataError,
            pymysql.err.InternalError,
            pymysql.err.NotSupportedError,
        ) as exc:
            raise OperationalError(exc)
        except pymysql.err.IntegrityError as exc:
            raise IntegrityError(exc)

    return translate_exceptions_  # type: ignore


class MySQLClient(BaseDBAsyncClient):
    query_class = MySQLQuery
    executor_class = MySQLExecutor
    schema_generator = MySQLSchemaGenerator
    capabilities = Capabilities("mysql", requires_limit=True, inline_comment=True)

    def acquire_connection(self) -> Union["ConnectionWrapper", "PoolConnectionWrapper"]:
        return PoolConnectionWrapper(self._pool)

    @translate_exceptions
    async def execute_query(
        self, query: str, values: Optional[list] = None
    ) -> Tuple[int, List[dict]]:
        async with self.acquire_connection() as connection:
            self.log.debug("%s: %s", query, values)
            async with connection.cursor() as cursor:
                await cursor.execute(query, values)
                rows = await cursor.fetchall()
                if rows:
                    fields = [f.name for f in cursor._result.fields]
                    return cursor.rowcount, [dict(zip(fields, row)) for row in rows]
                return cursor.rowcount, []
