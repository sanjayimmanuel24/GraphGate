import operator
from functools import partial
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple

from pypika import Table
from pypika.functions import Upper
from pypika.terms import (
    BasicCriterion,
    Criterion,
    Enum,
    Equality,
    Term,
    ValueWrapper,
    basestring,
    date,
    format_quotes,
)

from tortoise.fields import Field
from tortoise.fields.relational import BackwardFKRelation, ManyToManyFieldInstance

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model


class Like(BasicCriterion):  # type: ignore
    def __init__(self, left, right, alias=None, escape=" ESCAPE '\\'") -> None:
        """
        A Like that supports an ESCAPE clause
        """
        super().__init__(" LIKE ", left, right, alias=alias)
        self.escape = escape

    def get_sql(self, quote_char='"', with_alias=False, **kwargs):
        sql = "{left}{comparator}{right}{escape}".format(
            comparator=self.comparator,
            left=self.left.get_sql(quote_char=quote_char, **kwargs),
            right=self.right.get_sql(quote_char=quote_char, **kwargs),
            escape=self.escape,
        )
        if with_alias and self.alias:  # pragma: nocoverage
            return '{sql} "{alias}"'.format(sql=sql, alias=self.alias)
        return sql


def escape_like(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def string_encoder(value: Any, instance: "Model", field: Field) -> str:
    return str(value)


def contains(field: Term, value: str) -> Criterion:
    return Like(field, field.wrap_constant(f"%{escape_like(value)}%"))


def starts_with(field: Term, value: str) -> Criterion:
    return Like(field, field.wrap_constant(f"{escape_like(value)}%"))


def ends_with(field: Term, value: str) -> Criterion:
    return Like(field, field.wrap_constant(f"%{escape_like(value)}"))


def insensitive_exact(field: Term, value: str) -> Criterion:
    return Upper(field).eq(Upper(str(value)))


def insensitive_contains(field: Term, value: str) -> Criterion:
    return Like(Upper(field), field.wrap_constant(Upper(f"%{escape_like(value)}%")))


def insensitive_starts_with(field: Term, value: str) -> Criterion:
    return Like(Upper(field), field.wrap_constant(Upper(f"{escape_like(value)}%")))


def insensitive_ends_with(field: Term, value: str) -> Criterion:
    return Like(Upper(field), field.wrap_constant(Upper(f"%{escape_like(value)}")))
