import inspect
import re
from copy import copy, deepcopy
from functools import partial
from typing import Any, Awaitable, Dict, Generator, List, Optional, Set, Tuple, Type, TypeVar

from pypika import Order, Query, Table

from tortoise.backends.base.client import BaseDBAsyncClient
from tortoise.exceptions import (
    ConfigurationError,
    IncompleteInstanceError,
    IntegrityError,
    OperationalError,
    TransactionManagementError,
)
from tortoise.fields.base import Field
from tortoise.fields.data import IntField
from tortoise.fields.relational import (
    BackwardFKRelation,
    BackwardOneToOneRelation,
    ForeignKeyFieldInstance,
    ManyToManyFieldInstance,
    ManyToManyRelation,
    NoneAwaitable,
    OneToOneFieldInstance,
    ReverseRelation,
)
from tortoise.filters import get_filters_for_field
from tortoise.functions import Function
from tortoise.queryset import Q, QuerySet, QuerySetSingle
from tortoise.transactions import current_transaction_map, in_transaction


class MetaInfo:
    __slots__ = (
        "abstract",
        "db_table",
        "app",
        "fields",
        "db_fields",
        "m2m_fields",
        "o2o_fields",
        "backward_o2o_fields",
        "fk_fields",
        "backward_fk_fields",
        "fetch_fields",
        "fields_db_projection",
        "_inited",
        "fields_db_projection_reverse",
        "filters",
        "fields_map",
        "default_connection",
        "basequery",
        "basequery_all_fields",
        "basetable",
        "_filters",
        "unique_together",
        "indexes",
        "pk_attr",
        "generated_db_fields",
        "_model",
        "table_description",
        "pk",
        "db_pk_column",
        "db_native_fields",
        "db_default_fields",
        "db_complex_fields",
        "_default_ordering",
        "_ordering_validated",
    )

    def get_filter(self, key: str) -> dict:
        return self.filters[key]

    def _generate_filters(self) -> None:
        get_overridden_filter_func = self.db.executor_class.get_overridden_filter_func
        for key, filter_info in self._filters.items():
            overridden_operator = get_overridden_filter_func(
                filter_func=filter_info["operator"]  # type: ignore
            )
            if overridden_operator:
                filter_info = copy(filter_info)
                filter_info["operator"] = overridden_operator  # type: ignore
            self.filters[key] = filter_info
