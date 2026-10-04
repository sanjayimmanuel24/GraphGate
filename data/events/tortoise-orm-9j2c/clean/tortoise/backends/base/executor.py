import asyncio
import datetime
import decimal
from copy import copy
from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union, cast

from pypika import JoinType, Parameter, Query, Table

from tortoise.exceptions import OperationalError
from tortoise.fields.base import Field
from tortoise.fields.relational import (
    BackwardFKRelation,
    BackwardOneToOneRelation,
    ManyToManyFieldInstance,
    RelationalField,
)
from tortoise.query_utils import QueryModifier

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model
    from tortoise.backends.base.client import BaseDBAsyncClient
    from tortoise.query_utils import Prefetch
    from tortoise.queryset import QuerySet


class BaseExecutor:
    TO_DB_OVERRIDE: Dict[Type[Field], Callable] = {}
    FILTER_FUNC_OVERRIDE: Dict[Callable, Callable] = {}
    EXPLAIN_PREFIX: str = "EXPLAIN"
    DB_NATIVE = {bytes, str, int, float, decimal.Decimal, datetime.datetime, datetime.date}

    async def execute_select(self, query: Query, custom_fields: Optional[list] = None) -> list:
        _, raw_results = await self.db.execute_query(query.get_sql())
        instance_list = []
        for row in raw_results:
            instance: "Model" = self.model._init_from_db(**row)
            if custom_fields:
                for field in custom_fields:
                    setattr(instance, field, row[field])
            instance_list.append(instance)
        await self._execute_prefetch_queries(instance_list)
        return instance_list

    @classmethod
    def get_overridden_filter_func(cls, filter_func: Callable) -> Optional[Callable]:
        return cls.FILTER_FUNC_OVERRIDE.get(filter_func)
