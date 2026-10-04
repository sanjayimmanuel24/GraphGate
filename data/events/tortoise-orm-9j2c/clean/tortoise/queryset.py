import types
from copy import copy
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Generator,
    Generic,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from pypika import JoinType, Order, Table
from pypika.functions import Count
from pypika.queries import QueryBuilder
from pypika.terms import Term
from typing_extensions import Protocol

from tortoise.backends.base.client import BaseDBAsyncClient, Capabilities
from tortoise.exceptions import (
    DoesNotExist,
    FieldError,
    IntegrityError,
    MultipleObjectsReturned,
    ParamsError,
)
from tortoise.expressions import F
from tortoise.fields.relational import (
    ForeignKeyFieldInstance,
    OneToOneFieldInstance,
    RelationalField,
)
from tortoise.functions import Function
from tortoise.query_utils import Prefetch, Q, QueryModifier, _get_joins_for_related_field

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model

MODEL = TypeVar("MODEL", bound="Model")


class AwaitableQuery(Generic[MODEL]):
    __slots__ = ("_joined_tables", "query", "model", "_db", "capabilities", "_annotations")

    def resolve_filters(
        self,
        model: "Type[Model]",
        q_objects: List[Q],
        annotations: Dict[str, Any],
        custom_filters: Dict[str, Dict[str, Any]],
    ) -> None:
        """
        Builds the common filters for a QuerySet.

        :param model: The Model this querysit is based on.
        :param q_objects: The Q expressions to apply.
        :param annotations: Extra annotations to add.
        :param custom_filters: Pre-resolved filters to be passed though.
        """
        has_aggregate = self._resolve_annotate()

        modifier = QueryModifier()
        for node in q_objects:
            modifier &= node.resolve(model, annotations, custom_filters, model._meta.basetable)

        where_criterion, joins, having_criterion = modifier.get_query_modifiers()
        for join in joins:
            if join[0] not in self._joined_tables:
                self.query = self.query.join(join[0], how=JoinType.left_outer).on(join[1])
                self._joined_tables.append(join[0])

        self.query._wheres = where_criterion
        self.query._havings = having_criterion

        if has_aggregate and (self._joined_tables or having_criterion):
            self.query = self.query.groupby(
                self.model._meta.basetable[self.model._meta.db_pk_column]
            )


class QuerySet(AwaitableQuery[MODEL]):
    __slots__ = (
        "fields",
        "_prefetch_map",
        "_prefetch_queries",
        "_single",
        "_raise_does_not_exist",
        "_db",
        "_limit",
        "_offset",
        "_fields_for_select",
        "_filter_kwargs",
        "_orderings",
        "_q_objects",
        "_distinct",
        "_having",
        "_custom_filters",
    )

    def _filter_or_exclude(self, *args: Q, negate: bool, **kwargs: Any) -> "QuerySet[MODEL]":
        queryset = self._clone()
        for arg in args:
            if not isinstance(arg, Q):
                raise TypeError("expected Q objects as args")
            if negate:
                queryset._q_objects.append(~arg)
            else:
                queryset._q_objects.append(arg)

        for key, value in kwargs.items():
            if negate:
                queryset._q_objects.append(~Q(**{key: value}))
            else:
                queryset._q_objects.append(Q(**{key: value}))

        return queryset

    def filter(self, *args: Q, **kwargs: Any) -> "QuerySet[MODEL]":
        """
        Filters QuerySet by given kwargs. You can filter by related objects like this:

        .. code-block:: python3

            Team.filter(events__tournament__name='Test')

        You can also pass Q objects to filters as args.
        """
        return self._filter_or_exclude(negate=False, *args, **kwargs)

    def _make_query(self) -> None:
        if self._fields_for_select:
            table = self.model._meta.basetable
            db_fields_for_select = [
                table[self.model._meta.fields_db_projection[field]].as_(field)
                for field in self._fields_for_select
            ]
            self.query = copy(self.model._meta.basequery).select(*db_fields_for_select)
        else:
            self.query = copy(self.model._meta.basequery_all_fields)
        self.resolve_filters(
            model=self.model,
            q_objects=self._q_objects,
            annotations=self._annotations,
            custom_filters=self._custom_filters,
        )
        if self._limit:
            self.query._limit = self._limit
        if self._offset:
            self.query._offset = self._offset
        if self._distinct:
            self.query._distinct = True
        self.resolve_ordering(
            self.model, self.model._meta.basetable, self._orderings, self._annotations
        )

    def __await__(self) -> Generator[Any, None, List[MODEL]]:
        if self._db is None:
            self._db = self.model._meta.db  # type: ignore
        self._make_query()
        return self._execute().__await__()

    async def _execute(self) -> List[MODEL]:
        instance_list = await self._db.executor_class(
            model=self.model,
            db=self._db,
            prefetch_map=self._prefetch_map,
            prefetch_queries=self._prefetch_queries,
        ).execute_select(self.query, custom_fields=list(self._annotations.keys()))
        if self._single:
            if len(instance_list) == 1:
                return instance_list[0]
            if not instance_list:
                if self._raise_does_not_exist:
                    raise DoesNotExist("Object does not exist")
                return None  # type: ignore
            raise MultipleObjectsReturned("Multiple objects returned, expected exactly one")
        return instance_list
