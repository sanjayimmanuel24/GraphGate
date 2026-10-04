from __future__ import annotations

import contextvars
import typing as t
from dataclasses import dataclass

from piccolo.engine.base import Batch, Engine
from piccolo.engine.exceptions import TransactionError
from piccolo.query.base import DDL, Query
from piccolo.querystring import QueryString
from piccolo.utils.lazy_loader import LazyLoader
from piccolo.utils.sync import run_sync
from piccolo.utils.warnings import Level, colored_warning

asyncpg = LazyLoader("asyncpg", globals(), "asyncpg")

if t.TYPE_CHECKING:  # pragma: no cover
    from asyncpg.connection import Connection
    from asyncpg.cursor import Cursor
    from asyncpg.pool import Pool


class Savepoint:
    def __init__(self, name: str, transaction: PostgresTransaction):
        self.name = name
        self.transaction = transaction

    async def rollback_to(self):
        await self.transaction.connection.execute(
            f"ROLLBACK TO SAVEPOINT {self.name}"
        )

    async def release(self):
        await self.transaction.connection.execute(
            f"RELEASE SAVEPOINT {self.name}"
        )


class PostgresTransaction:
    """
    Used for wrapping queries in a transaction, using a context manager.
    Currently it's async only.

    Usage::

        async with engine.transaction():
            # Run some queries:
            await Band.select().run()

    """

    __slots__ = (
        "engine",
        "transaction",
        "context",
        "connection",
        "_savepoint_id",
        "_parent",
        "_committed",
        "_rolled_back",
    )

    def __init__(self, engine: PostgresEngine, allow_nested: bool = True):
        """
        :param allow_nested:
            If ``True`` then if we try creating a new transaction when another
            is already active, we treat this as a no-op::

                async with DB.transaction():
                    async with DB.transaction():
                        pass

            If we want to disallow this behaviour, then setting
            ``allow_nested=False`` will cause a ``TransactionError`` to be
            raised.

        """
        self.engine = engine
        current_transaction = self.engine.current_transaction.get()

        self._savepoint_id = 0
        self._parent = None
        self._committed = False
        self._rolled_back = False

        if current_transaction:
            if allow_nested:
                self._parent = current_transaction
            else:
                raise TransactionError(
                    "A transaction is already active - nested transactions "
                    "aren't allowed."
                )

    async def __aenter__(self) -> PostgresTransaction:
        if self._parent is not None:
            return self._parent

        self.connection = await self.get_connection()
        self.transaction = self.connection.transaction()
        await self.begin()
        self.context = self.engine.current_transaction.set(self)
        return self

    async def get_connection(self):
        if self.engine.pool:
            return await self.engine.pool.acquire()
        else:
            return await self.engine.get_new_connection()

    async def begin(self):
        await self.transaction.start()

    async def commit(self):
        await self.transaction.commit()
        self._committed = True

    async def rollback(self):
        await self.transaction.rollback()
        self._rolled_back = True

    async def rollback_to(self, savepoint_name: str):
        """
        Used to rollback to a savepoint just using the name.
        """
        await Savepoint(name=savepoint_name, transaction=self).rollback_to()

    ###########################################################################

    def get_savepoint_id(self) -> int:
        self._savepoint_id += 1
        return self._savepoint_id

    async def savepoint(self, name: t.Optional[str] = None) -> Savepoint:
        name = name or f"savepoint_{self.get_savepoint_id()}"
        await self.connection.execute(f"SAVEPOINT {name}")
        return Savepoint(name=name, transaction=self)

    ###########################################################################

    async def __aexit__(self, exception_type, exception, traceback):
        if self._parent:
            return exception is None

        if exception:
            # The user may have manually rolled it back.
            if not self._rolled_back:
                await self.rollback()
        else:
            # The user may have manually committed it.
            if not self._committed and not self._rolled_back:
                await self.commit()

        if self.engine.pool:
            await self.engine.pool.release(self.connection)
        else:
            await self.connection.close()

        self.engine.current_transaction.reset(self.context)

        return exception is None


class PostgresEngine(Engine[t.Optional[PostgresTransaction]]):
    """
    Used to connect to PostgreSQL.

    :param config:
        The config dictionary is passed to the underlying database adapter,
        asyncpg. Common arguments you're likely to need are:

        * host
        * port
        * user
        * password
        * database

        For example, ``{'host': 'localhost', 'port': 5432}``.

        See the `asyncpg docs <https://magicstack.github.io/asyncpg/current/api/index.html#connection>`_
        for all available options.

    :param extensions:
        When the engine starts, it will try and create these extensions
        in Postgres. If you're using a read only database, set this value to an
        empty tuple ``()``.

    :param log_queries:
        If ``True``, all SQL and DDL statements are printed out before being
        run. Useful for debugging.

    :param log_responses:
        If ``True``, the raw response from each query is printed out. Useful
        for debugging.

    :param extra_nodes:
        If you have additional database nodes (e.g. read replicas) for the
        server, you can specify them here. It's a mapping of a memorable name
        to a ``PostgresEngine`` instance. For example::

            DB = PostgresEngine(
                config={'database': 'main_db'},
                extra_nodes={
                    'read_replica_1': PostgresEngine(
                        config={
                            'database': 'main_db',
                            host: 'read_replicate.my_db.com'
                        },
                        extensions=()
                    )
                }
            )

        Note how we set ``extensions=()``, because it's a read only database.

        When executing a query, you can specify one of these nodes instead
        of the main database. For example::

            >>> await MyTable.select().run(node="read_replica_1")

    """  # noqa: E501

    __slots__ = (
        "config",
        "extensions",
        "log_queries",
        "log_responses",
        "extra_nodes",
        "pool",
        "current_transaction",
    )

    engine_type = "postgres"
    min_version_number = 10

    def __init__(
        self,
        config: t.Dict[str, t.Any],
        extensions: t.Sequence[str] = ("uuid-ossp",),
        log_queries: bool = False,
        log_responses: bool = False,
        extra_nodes: t.Mapping[str, PostgresEngine] = None,
    ) -> None:
        if extra_nodes is None:
            extra_nodes = {}

        self.config = config
        self.extensions = extensions
        self.log_queries = log_queries
        self.log_responses = log_responses
        self.extra_nodes = extra_nodes
        self.pool: t.Optional[Pool] = None
        database_name = config.get("database", "Unknown")
        self.current_transaction = contextvars.ContextVar(
            f"pg_current_transaction_{database_name}", default=None
        )
        super().__init__()

    async def get_new_connection(self) -> Connection:
        """
        Returns a new connection - doesn't retrieve it from the pool.
        """
        return await asyncpg.connect(**self.config)

    def transaction(self, allow_nested: bool = True) -> PostgresTransaction:
        return PostgresTransaction(engine=self, allow_nested=allow_nested)
