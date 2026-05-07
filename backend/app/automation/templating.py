from typing import Any


def render_mapping(values: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    return {key: render_value(value, context) for key, value in values.items()}


def render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: render_value(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render_value(item, context) for item in value]
    if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
        return resolve_expr(value[2:-2].strip(), context)
    return value


def resolve_expr(expr: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for part in expr.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"Cannot resolve template expression: {expr}")
        current = current[part]
    return current
