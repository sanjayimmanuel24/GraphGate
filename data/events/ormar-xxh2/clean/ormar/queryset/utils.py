import collections.abc
import copy
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)

if TYPE_CHECKING:  # pragma no cover
    from ormar import BaseField, Model


def get_relationship_alias_model_and_str(
    source_model: Type["Model"], related_parts: List
) -> Tuple[str, Type["Model"], str, bool]:
    """
    Walks the relation to retrieve the actual model on which the clause should be
    constructed, extracts alias based on last relation leading to target model.
    :param related_parts: list of related names extracted from string
    :type related_parts: Union[List, List[str]]
    :param source_model: model from which relation starts
    :type source_model: Type[Model]
    :return: table prefix, target model and relation string
    :rtype: Tuple[str, Type["Model"], str]
    """
    table_prefix = ""
    is_through = False
    target_model = source_model
    previous_model = target_model
    previous_models = [target_model]
    manager = target_model.ormar_config.alias_manager
    for relation in related_parts[:]:
        related_field = target_model.ormar_config.model_fields[relation]

        if related_field.is_through:
            previous_model, relation, is_through = _process_through_field(
                related_parts=related_parts,
                relation=relation,
                related_field=related_field,
                previous_model=previous_model,
                previous_models=previous_models,
            )
        if related_field.is_multi:
            previous_model = related_field.through
            relation = related_field.default_target_field_name()  # type: ignore
        table_prefix = manager.resolve_relation_alias(
            from_model=previous_model, relation_name=relation
        )
        target_model = related_field.to
        previous_model = target_model
        if not is_through:
            previous_models.append(previous_model)
    relation_str = "__".join(related_parts)

    return table_prefix, target_model, relation_str, is_through


def _process_through_field(
    related_parts: List,
    relation: Optional[str],
    related_field: "BaseField",
    previous_model: Type["Model"],
    previous_models: List[Type["Model"]],
) -> Tuple[Type["Model"], Optional[str], bool]:
    """
    Helper processing through models as they need to be treated differently.

    :param related_parts: split relation string
    :type related_parts: List[str]
    :param relation: relation name
    :type relation: str
    :param related_field: field with relation declaration
    :type related_field: "ForeignKeyField"
    :param previous_model: model from which relation is coming
    :type previous_model: Type["Model"]
    :param previous_models: list of already visited models in relation chain
    :type previous_models: List[Type["Model"]]
    :return: previous_model, relation, is_through
    :rtype: Tuple[Type["Model"], str, bool]
    """
    is_through = True
    related_parts.remove(relation)
    through_field = related_field.owner.ormar_config.model_fields[
        related_field.related_name or ""
    ]
    if len(previous_models) > 1 and previous_models[-2] == through_field.to:
        previous_model = through_field.to
        relation = through_field.related_name
    else:
        relation = related_field.related_name
    return previous_model, relation, is_through
