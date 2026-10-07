"""Parse blocklists and whitelists into clean, de-duplicated domain sets."""

from __future__ import annotations

from typing import Optional

from .config import DOMAIN_PATTERN, IP_PATTERN, REPLACE_PATTERN
from .log import info

_LOCAL_BLOCK_IPS = ("127.0.0.1", "0.0.0.0")


def convert_to_block_list(
    block_content: str, exception_domains: Optional[set[str]] = None
) -> list[str]:
    """Convert a blocklist into a sorted list of Cloudflare domains.

    AdBlock exception rules (for example ``@@||example.com^``) are not block
    entries. When ``exception_domains`` is supplied, their domains are
    collected there so the caller can promote them into the Allow list.
    """
    block_domains: set[str] = set()
    extract_domains(block_content, block_domains, exception_domains)
    info(f"Number of blocked domains: {len(block_domains)}")

    final_domains = sorted(remove_redundant_subdomains(block_domains))
    info(f"Number of final block domains: {len(final_domains)}")
    return final_domains


def convert_to_allow_list(white_content: str) -> list[str]:
    """Convert a whitelist into a sorted list of Cloudflare domains."""
    white_domains: set[str] = set()
    extract_domains(white_content, white_domains)
    info(f"Number of whitelisted domains: {len(white_domains)}")

    final_domains = sorted(white_domains)
    info(f"Number of final allow domains: {len(final_domains)}")
    return final_domains


def extract_domains(
    content: str,
    domains: set[str],
    exception_domains: Optional[set[str]] = None,
) -> None:
    """Extract valid domains from ``content`` into ``domains``.

    Handles hosts files, AdBlock/uBlock syntax and plain domain lists. AdBlock
    exception rules are routed to ``exception_domains`` when provided.
    """
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith(("#", "!", "/")) or line == "":
            continue

        # Hosts-file entries are only valid for local blocking addresses.
        # Skip entries mapped to any other IP, e.g.:
        #   110.43.121.13 bigota.d.miui.com
        # Allowed: 127.0.0.1 example.com / 0.0.0.0 example.com
        parts = line.split()
        if len(parts) >= 2 and IP_PATTERN.match(parts[0]):
            if parts[0] not in _LOCAL_BLOCK_IPS:
                continue

        # AdBlock/uBlock exception: @@||example.com^ means "allow this
        # domain", so it must not be turned into a normal block entry.
        is_exception = line.lower().startswith("@@||")

        cleaned_line = line.lower().split("#")[0].split("^")[0].replace("\r", "")
        domain = REPLACE_PATTERN.sub("", cleaned_line, count=1)

        # Strip a residual wildcard, e.g. "||*.adtech.de" or "0.0.0.0 *.foo.com".
        if domain.startswith("*."):
            domain = domain[2:]

        # Single-label names (localhost, broadcasthost, ...) are not blockable
        # internet domains.
        if "." not in domain:
            continue

        try:
            domain = domain.encode("idna").decode("utf-8", "replace")
        except UnicodeError:
            continue

        if not DOMAIN_PATTERN.match(domain) or IP_PATTERN.match(domain):
            continue

        if is_exception:
            if exception_domains is not None:
                exception_domains.add(domain)
        else:
            domains.add(domain)


def remove_redundant_subdomains(domains: set[str]) -> set[str]:
    """Drop domains that are already covered by a parent domain in the set."""
    top_level_domains: set[str] = set()

    for domain in domains:
        parts = domain.split(".")
        is_lower_subdomain = any(
            ".".join(parts[index:]) in domains for index in range(1, len(parts))
        )
        if not is_lower_subdomain:
            top_level_domains.add(domain)

    return top_level_domains
