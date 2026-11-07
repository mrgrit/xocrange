"""Shared RFC 3339 subset, independent of optional jsonschema dependencies."""
from datetime import datetime
import re

RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)


def parse_timestamp(value):
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        raise ValueError("Expected RFC 3339 timestamp with timezone")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
