import asyncio
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncGenerator,
    Dict,
    Generic,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import sqlalchemy
from sqlalchemy import bindparam

import ormar  # noqa I100
from ormar import MultipleMatches, NoMatch
from ormar.exceptions import (
    ModelListEmptyError,
    ModelPersistenceError,
    QueryDefinitionError,
)
from ormar.queryset import FieldAccessor, FilterQuery, SelectAction
from ormar.queryset.actions.order_action import OrderAction
from ormar.queryset.clause import FilterGroup, QueryClause
from ormar.queryset.queries.prefetch_query import PrefetchQuery
from ormar.queryset.queries.query import Query
from ormar.queryset.reverse_alias_resolver import ReverseAliasResolver

if TYPE_CHECKING:  # pragma no cover
    from ormar import Model
    from ormar.models import T
    from ormar.models.excludable import ExcludableItems
    from ormar.models.ormar_config import OrmarConfig
else:
    T = TypeVar("T", bound="Model")


class QuerySet(Generic[T]):
    """
    Main class to perform database queries, exposed on each model as objects attribute.
    """

    def __init__(  # noqa CFQ002
        self,
        model_cls: Optional[Type["T"]] = None,
        filter_clauses: Optional[List] = None,
        exclude_clauses: Optional[List] = None,
        select_related: Optional[List] = None,
        limit_count: Optional[int] = None,
        offset: Optional[int] = None,
        excludable: Optional["ExcludableItems"] = None,
        order_bys: Optional[List] = None,
        prefetch_related: Optional[List] = None,
        limit_raw_sql: bool = False,
        proxy_source_model: Optional[Type["Model"]] = None,
    ) -> None:
        self.proxy_source_model = proxy_source_model
        self.model_cls = model_cls
        self.filter_clauses = [] if filter_clauses is None else filter_clauses
        self.exclude_clauses = [] if exclude_clauses is None else exclude_clauses
        self._select_related = [] if select_related is None else select_related
        self._prefetch_related = [] if prefetch_related is None else prefetch_related
        self.limit_count = limit_count
        self.query_offset = offset
        self._excludable = excludable or ormar.ExcludableItems()
        self.order_bys = order_bys or []
        self.limit_sql_raw = limit_raw_sql

    @property
    def model_config(self) -> "OrmarConfig":
        """
        Shortcut to model class OrmarConfig set on QuerySet model.

        :return: OrmarConfig of the model
        :rtype: model's OrmarConfig
        """
        if not self.model_cls:  # pragma nocover
            raise ValueError("Model class of QuerySet is not initialized")
        return self.model_cls.ormar_config

    @property
    def model(self) -> Type["T"]:
        """
        Shortcut to model class set on QuerySet.

        :return: model class
        :rtype: Type[Model]
        """
        if not self.model_cls:  # pragma nocover
            raise ValueError("Model class of QuerySet is not initialized")
        return self.model_cls

    def build_select_expression(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        order_bys: Optional[List] = None,
    ) -> sqlalchemy.sql.Select:
        """
        Constructs the actual database query used in the QuerySet.
        If any of the params is not passed the QuerySet own value is used.

        :param limit: number to limit the query
        :type limit: int
        :param offset: number to offset by
        :type offset: int
        :param order_bys: list of order-by fields names
        :type order_bys: List
        :return: built sqlalchemy select expression
        :rtype: sqlalchemy.sql.selectable.Select
        """
        qry = Query(
            model_cls=self.model,
            select_related=self._select_related,
            filter_clauses=self.filter_clauses,
            exclude_clauses=self.exclude_clauses,
            offset=offset or self.query_offset,
            excludable=self._excludable,
            order_bys=order_bys or self.order_bys,
            limit_raw_sql=self.limit_sql_raw,
            limit_count=limit if limit is not None else self.limit_count,
        )
        exp = qry.build_select_expression()
        # print("\n", exp.compile(compile_kwargs={"literal_binds": True}))
        return exp

    async def _query_aggr_function(self, func_name: str, columns: List) -> Any:
        func = getattr(sqlalchemy.func, func_name)
        select_actions = [
            SelectAction(select_str=column, model_cls=self.model) for column in columns
        ]
        if func_name in ["sum", "avg"]:
            if any(not x.is_numeric for x in select_actions):
                raise QueryDefinitionError(
                    "You can use sum and svg only with" "numeric types of columns"
                )
        select_columns = [x.apply_func(func, use_label=True) for x in select_actions]
        expr = self.build_select_expression().alias(f"subquery_for_{func_name}")
        expr = sqlalchemy.select(*select_columns).select_from(expr)  # type: ignore
        # print("\n", expr.compile(compile_kwargs={"literal_binds": True}))
        async with self.model_config.database.get_query_executor() as executor:
            result = await executor.fetch_one(expr)  # type: ignore
        return dict(result) if len(result) > 1 else result[columns[0]]  # type: ignore

    async def max(self, columns: Union[str, List[str]]) -> Any:  # noqa: A003
        """
        Returns max value of columns for rows matching the given criteria
        (applied with `filter` and `exclude` if set before).

        :return: max value of column(s)
        :rtype: Any
        """
        if not isinstance(columns, list):
            columns = [columns]
        return await self._query_aggr_function(func_name="max", columns=columns)

    async def min(self, columns: Union[str, List[str]]) -> Any:  # noqa: A003
        """
        Returns min value of columns for rows matching the given criteria
        (applied with `filter` and `exclude` if set before).

        :return: min value of column(s)
        :rtype: Any
        """
        if not isinstance(columns, list):
            columns = [columns]
        return await self._query_aggr_function(func_name="min", columns=columns)

    async def sum(self, columns: Union[str, List[str]]) -> Any:  # noqa: A003
        """
        Returns sum value of columns for rows matching the given criteria
        (applied with `filter` and `exclude` if set before).

        :return: sum value of columns
        :rtype: int
        """
        if not isinstance(columns, list):
            columns = [columns]
        return await self._query_aggr_function(func_name="sum", columns=columns)

    async def avg(self, columns: Union[str, List[str]]) -> Any:
        """
        Returns avg value of columns for rows matching the given criteria
        (applied with `filter` and `exclude` if set before).

        :return: avg value of columns
        :rtype: Union[int, float, List]
        """
        if not isinstance(columns, list):
            columns = [columns]
        return await self._query_aggr_function(func_name="avg", columns=columns)
