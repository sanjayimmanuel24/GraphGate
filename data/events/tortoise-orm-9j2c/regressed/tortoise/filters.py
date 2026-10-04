import operator
from functools import partial
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple

from pypika import Table
from pypika.functions import Upper
from pypika.terms import BasicCriterion, Criterion, Equality, Term, ValueWrapper

from tortoise.fields import Field
from tortoise.fields.relational import BackwardFKRelation, ManyToManyFieldInstance

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model


def string_encoder(value: Any, instance: "Model", field: Field) -> str:
    return str(value)


def contains(field: Term, value: str) -> Criterion:
    return field.like(f"%{value}%")


def starts_with(field: Term, value: str) -> Criterion:
    return field.like(f"{value}%")


def ends_with(field: Term, value: str) -> Criterion:
    return field.like(f"%{value}")


def insensitive_exact(field: Term, value: str) -> Criterion:
    return Upper(field).eq(Upper(f"{value}"))


def insensitive_contains(field: Term, value: str) -> Criterion:
    return Upper(field).like(Upper(f"%{value}%"))


def insensitive_starts_with(field: Term, value: str) -> Criterion:
    return Upper(field).like(Upper(f"{value}%"))


def insensitive_ends_with(field: Term, value: str) -> Criterion:
    return Upper(field).like(Upper(f"%{value}"))
