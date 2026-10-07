"""Local cache and GitHub Actions housekeeping helpers.

The cache keeps track of Cloudflare list/rule ids, the domains in each list
(forward mapping), the reverse mapping, and a hash of the desired domain set
per prefix so unchanged syncs can be skipped.
"""

from __future__ import annotations

import hashlib
import json
import os

from .api import get_list_items, get_lists, get_rules
from .config import CACHE_FILE, GITHUB_REPOSITORY, IDS_PATTERN
from .github_api import GithubAPI

Cache = dict


def _empty_cache() -> Cache:
    return {"lists": [], "rules": [], "mapping": {}}


def _read_cache_file(default: Cache) -> Cache:
    if not CACHE_FILE.exists():
        return default
    try:
        with CACHE_FILE.open(encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def load_cache() -> Cache:
    """Load the cache, trusting it only after a successful workflow run."""
    if is_running_in_github_actions():
        status, completed_run_ids = get_latest_workflow_status()
        delete_completed_workflows(completed_run_ids)
        if status == "success":
            return _read_cache_file(_empty_cache())
        return _empty_cache()
    return _read_cache_file(_empty_cache())


def save_cache(cache: Cache) -> None:
    with CACHE_FILE.open("w", encoding="utf-8") as file:
        json.dump(cache, file)


def get_current_lists(cache: Cache, list_name: str) -> list[dict]:
    """Return cached lists matching ``list_name`` (fetching on cache miss)."""
    cached = [lst for lst in cache["lists"] if lst["name"].startswith(list_name)]
    if cached:
        return cached

    current_lists = get_lists(list_name)
    existing_ids = {lst["id"] for lst in cache["lists"]}
    for lst in current_lists:
        if lst["id"] not in existing_ids:
            cache["lists"].append(lst)
    save_cache(cache)
    return current_lists


def get_current_rules(cache: Cache, rule_name: str) -> list[dict]:
    """Return cached rules matching ``rule_name`` (fetching on cache miss)."""
    cached = [rule for rule in cache["rules"] if rule["name"].startswith(rule_name)]
    if cached:
        return cached

    current_rules = get_rules(rule_name)
    existing_ids = {rule["id"] for rule in cache["rules"]}
    for rule in current_rules:
        if rule["id"] not in existing_ids:
            cache["rules"].append(rule)
    save_cache(cache)
    return current_rules


def get_list_items_cached(cache: Cache, list_id: str) -> list[str]:
    if list_id in cache["mapping"]:
        return cache["mapping"][list_id]
    items = get_list_items(list_id)
    cache["mapping"][list_id] = items
    save_cache(cache)
    return items


def compute_domain_hash(domains) -> str:
    """Deterministic hash of a domain collection, used to skip no-op syncs."""
    return hashlib.sha256("\n".join(sorted(domains)).encode()).hexdigest()


def get_cached_domain_state(cache: Cache, prefix: str) -> tuple[str | None, set[str]]:
    """Return ``(hash, cached_domain_set)`` for a list prefix."""
    entry = cache.setdefault("domain_hashes", {}).get(prefix)
    if entry is None:
        return None, set()
    return entry["hash"], set(entry["domains"])


def set_cached_domain_state(cache: Cache, prefix: str, domains) -> None:
    cache.setdefault("domain_hashes", {})[prefix] = {
        "hash": compute_domain_hash(domains),
        "domains": sorted(domains),
    }


def get_domain_diff(new_domains, cached_domains: set[str]) -> tuple[set[str], set[str]]:
    """Compute the exact add/remove sets between new and cached domains."""
    new_set = set(new_domains)
    return new_set - cached_domains, cached_domains - new_set


def get_cached_reverse_mapping(cache: Cache, prefix: str) -> dict[str, str]:
    """Return the ``{domain: list_id}`` reverse mapping for a prefix."""
    return cache.get("reverse_mappings", {}).get(prefix, {})


def set_cached_reverse_mapping(
    cache: Cache, prefix: str, mapping: dict[str, str]
) -> None:
    cache.setdefault("reverse_mappings", {})[prefix] = mapping


def build_reverse_mapping(
    cache: Cache, list_ids: list[str], prefix: str
) -> dict[str, str]:
    """Build ``{domain: list_id}`` from the cached forward mapping."""
    reverse: dict[str, str] = {}
    mapping = cache.get("mapping", {})
    prefix_lists = {
        lst["id"] for lst in cache.get("lists", []) if lst["name"].startswith(prefix)
    }
    for list_id in list_ids:
        if list_id in prefix_lists and list_id in mapping:
            for domain in mapping[list_id]:
                reverse[domain] = list_id
    return reverse


def extract_list_ids(rule: dict | None) -> set[str]:
    if not rule or not rule.get("traffic"):
        return set()
    return set(IDS_PATTERN.findall(rule["traffic"]))


def is_running_in_github_actions() -> bool:
    return os.getenv("GITHUB_ACTIONS") == "true"


def delete_completed_workflows(completed_run_ids: list[int]) -> None:
    for run_id in completed_run_ids:
        GithubAPI.delete(f"/repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}")


def get_latest_workflow_status() -> tuple[str | None, list[int]]:
    runs_url = f"/repos/{GITHUB_REPOSITORY}/actions/runs?per_page=5"
    runs = GithubAPI.get(runs_url).get("workflow_runs", [])
    completed_runs = [run for run in runs if run["status"] == "completed"]

    if completed_runs:
        latest_run = completed_runs[0]
        completed_run_ids = [run["id"] for run in completed_runs]
        return latest_run["conclusion"], completed_run_ids

    return None, []


def delete_cache() -> None:
    caches_url = f"/repos/{GITHUB_REPOSITORY}/actions/caches"
    caches = GithubAPI.get(caches_url).get("actions_caches", [])
    for cache_id in [cache["id"] for cache in caches]:
        GithubAPI.delete(f"{caches_url}/{cache_id}")
