"""Thin wrapper around the Cloudflare Gateway lists and rules endpoints."""

from __future__ import annotations

import json
from typing import Optional, Sequence

from .http_client import (
    RateLimitException,  # noqa: F401  (re-exported for callers)
    cloudflare_gateway_request,
    rate_limited_request,
    retry,
    retry_config,
)

API_DESCRIPTION = "Managed by Cloudflare-Gateway-DNS-Filter"


@retry(**retry_config)
@rate_limited_request
def create_list(name: str, domains: Sequence[str]) -> dict:
    endpoint = "/lists"
    data = {
        "name": name,
        "description": API_DESCRIPTION,
        "type": "DOMAIN",
        "items": [{"value": domain} for domain in domains],
    }
    _, response = cloudflare_gateway_request(
        "POST", endpoint, body=json.dumps(data)
    )
    return response["result"]


@retry(**retry_config)
@rate_limited_request
def update_list(
    list_id: str, remove_items: Sequence[str], append_items: Sequence[str]
) -> dict:
    endpoint = f"/lists/{list_id}"
    data = {
        "remove": list(remove_items),
        "append": [{"value": domain} for domain in append_items],
    }
    _, response = cloudflare_gateway_request(
        "PATCH", endpoint, body=json.dumps(data)
    )
    return response["result"]


def _rule_payload(
    rule_name: str,
    list_ids: Sequence[str],
    action: str,
    priority: int,
    filters: Optional[Sequence[str]],
    traffic_field: str,
) -> dict:
    payload = {
        "name": rule_name,
        "description": f"{API_DESCRIPTION} ({action})",
        "action": action,
        "precedence": priority,
        "traffic": " or ".join(f"any({traffic_field}[*] in ${lst})" for lst in list_ids),
        "enabled": True,
    }
    if filters:
        payload["filters"] = list(filters)
    return payload


@retry(**retry_config)
def create_rule(
    rule_name: str,
    list_ids: Sequence[str],
    action: str = "block",
    priority: int = 1000,
    filters: Optional[Sequence[str]] = None,
    traffic_field: str = "dns.domains",
) -> dict:
    data = _rule_payload(rule_name, list_ids, action, priority, filters, traffic_field)
    _, response = cloudflare_gateway_request(
        "POST", "/rules", body=json.dumps(data)
    )
    return response["result"]


@retry(**retry_config)
def update_rule(
    rule_name: str,
    rule_id: str,
    list_ids: Sequence[str],
    action: str = "block",
    priority: int = 1000,
    filters: Optional[Sequence[str]] = None,
    traffic_field: str = "dns.domains",
) -> dict:
    data = _rule_payload(rule_name, list_ids, action, priority, filters, traffic_field)
    endpoint = f"/rules/{rule_id}"
    _, response = cloudflare_gateway_request("PUT", endpoint, body=json.dumps(data))
    return response["result"]


@retry(**retry_config)
def get_lists(prefix_name: str) -> list[dict]:
    _, response = cloudflare_gateway_request("GET", "/lists")
    lists = response["result"] or []
    return [lst for lst in lists if lst["name"].startswith(prefix_name)]


@retry(**retry_config)
def get_rules(rule_name_prefix: str) -> list[dict]:
    _, response = cloudflare_gateway_request("GET", "/rules")
    rules = response["result"] or []
    return [rule for rule in rules if rule["name"].startswith(rule_name_prefix)]


@retry(**retry_config)
@rate_limited_request
def delete_list(list_id: str) -> dict:
    _, response = cloudflare_gateway_request("DELETE", f"/lists/{list_id}")
    return response["result"]


@retry(**retry_config)
def delete_rule(rule_id: str) -> dict:
    _, response = cloudflare_gateway_request("DELETE", f"/rules/{rule_id}")
    return response["result"]


@retry(**retry_config)
def get_list_items(list_id: str) -> list[str]:
    endpoint = f"/lists/{list_id}/items?limit=1000"
    _, response = cloudflare_gateway_request("GET", endpoint)
    items = response["result"] or []
    return [item["value"] for item in items]
