"""Bounded, duplicate-free data loading and packaged schema validation."""
from __future__ import annotations

import json
import math
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

import yaml
from jsonschema import Draft7Validator, FormatChecker

from .errors import XocError
from .timestamps import parse_timestamp

MAX_BYTES = 1_048_576


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise XocError("duplicate_key", "Document contains a duplicate key.")
        result[key] = value
    return result


def json_document(raw: bytes):
    if len(raw) > MAX_BYTES:
        raise XocError("input_too_large", "Input exceeds 1 MiB.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_float=finite_float,
                          parse_constant=lambda _: reject_constant())
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise XocError("invalid_json", "Expected bounded UTF-8 JSON.") from exc


def reject_constant():
    raise XocError("invalid_json", "Non-finite JSON numbers are not supported.")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        reject_constant()
    return number


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise XocError("yaml_alias", "YAML aliases are not supported.")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        pairs = []
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise XocError("invalid_key", "YAML keys must be strings.")
            pairs.append((key, self.construct_object(value_node, deep=deep)))
        return unique_object(pairs)


def read_bytes(path: Path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise XocError("unreadable_file", f"Cannot read file: {path.name}") from exc
    if len(raw) > MAX_BYTES:
        raise XocError("input_too_large", f"File exceeds 1 MiB: {path.name}")
    return raw


def yaml_document(path: Path):
    raw = read_bytes(path)
    try:
        return yaml.load(raw.decode("utf-8"), Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise XocError("invalid_yaml", f"Invalid YAML: {path.name}") from exc


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


@lru_cache(maxsize=None)
def validator(name: str):
    schema = json.loads(files("xocrange").joinpath("contracts", name + ".json").read_text())
    Draft7Validator.check_schema(schema)
    checker = FormatChecker()

    # jsonschema 3.x otherwise silently skips date-time without its optional package.
    @checker.checks("date-time", raises=(ValueError, TypeError))
    def date_time(value):
        if not isinstance(value, str):
            return True
        return parse_timestamp(value).tzinfo is not None

    return Draft7Validator(schema, format_checker=checker)


def validate(value, name: str):
    error = next(validator(name).iter_errors(value), None)
    if error:
        # jsonschema's full messages can contain credential-bearing input values.
        raise XocError("schema_violation", f"Document does not satisfy {name} ({error.validator}).")
    return value


def within(base: Path, relative: str, *, require_file=True) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise XocError("path_escape", "Paths must remain inside their package.")
    target = (base / rel).resolve()
    if not target.is_relative_to(base.resolve()):
        raise XocError("path_escape", "A symlink escapes its package.")
    if require_file and not target.is_file():
        raise XocError("missing_file", "A declared package file is missing.")
    return target
