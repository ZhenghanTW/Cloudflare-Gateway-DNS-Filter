"""Collect domains from remote adlists/whitelists and local dynamic files."""

from __future__ import annotations

import os
from configparser import ConfigParser, Error as ConfigParserError
from pathlib import Path
from typing import Optional

from .config import (
    ADLIST_FILE,
    DYNAMIC_BLACKLIST_FILE,
    DYNAMIC_WHITELIST_FILE,
    WHITELIST_FILE,
)
from .converter import convert_to_allow_list, convert_to_block_list
from .http_client import (
    HTTPException,
    RateLimitException,
    get_session,
    parse_retry_after,
    retry,
    retry_config,
)
from .log import info, warn

_DOWNLOAD_HEADERS = {"User-Agent": "Mozilla/5.0"}


class BaseDomainConverter:
    """Shared logic for downloading and reading list sources."""

    def read_urls_from_file(self, filename: Path | str) -> list[str]:
        path = Path(filename)
        if not path.exists():
            return []

        content = path.read_text(encoding="utf-8")
        try:
            parser = ConfigParser()
            parser.read_string(content)
        except ConfigParserError:
            return [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]

        return [
            parser.get(section, option)
            for section in parser.sections()
            for option in parser.options(section)
        ]

    def read_urls_from_env(self, env_var: str) -> list[str]:
        raw = os.getenv(env_var, "")
        return [url.strip() for url in raw.split() if url.strip()]

    def read_urls(self, env_var: str, file_path: Path | str) -> list[str]:
        return self.read_urls_from_file(file_path) + self.read_urls_from_env(env_var)

    @retry(**retry_config)
    def download_file(
        self, url: str, timeout: int = 15, max_redirects: int = 5
    ) -> str:
        response = get_session().request(
            "GET",
            url,
            headers=dict(_DOWNLOAD_HEADERS),
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects,
        )

        if response.status_code != 200:
            error_message = (
                f"Failed to download file from {url}, "
                f"status code: {response.status_code}"
            )
            warn(error_message)
            if response.status_code == 429:
                raise RateLimitException(
                    error_message,
                    retry_after=parse_retry_after(response.get_header("Retry-After")),
                )
            raise HTTPException(error_message)

        data = response.text
        info(f"Downloaded file from {url}. File size: {len(data)}")
        return data


class BlockDomainConverter(BaseDomainConverter):
    """Build the block domain list.

    Whitelist subtraction is NOT done here because the Allow rule in
    Cloudflare Gateway takes precedence.
    """

    def __init__(self) -> None:
        self.adlist_urls = self.read_urls("ADLIST_URLS", ADLIST_FILE)
        # Domains found in @@||... exception rules while processing the
        # blocklists. The manager promotes these into the Allow list.
        self.auto_whitelist_domains: set[str] = set()

    def process_urls(self) -> list[str]:
        block_content = "".join(
            self.download_file(url) for url in self.adlist_urls
        )

        dynamic_blacklist = os.getenv("DYNAMIC_BLACKLIST", "")
        if dynamic_blacklist:
            block_content += dynamic_blacklist
        else:
            block_content += _read_file(DYNAMIC_BLACKLIST_FILE)

        self.auto_whitelist_domains.clear()
        domains = convert_to_block_list(
            block_content, exception_domains=self.auto_whitelist_domains
        )
        info(
            f"Number of auto-whitelisted exceptions: "
            f"{len(self.auto_whitelist_domains)}"
        )
        return domains


class AllowDomainConverter(BaseDomainConverter):
    """Build the allow domain list."""

    def __init__(self) -> None:
        self.whitelist_urls = self.read_urls("WHITELIST_URLS", WHITELIST_FILE)

    def process_urls(self, extra_domains: Optional[set[str]] = None) -> list[str]:
        white_content = "".join(
            self.download_file(url) for url in self.whitelist_urls
        )

        dynamic_whitelist = os.getenv("DYNAMIC_WHITELIST", "")
        if dynamic_whitelist:
            white_content += dynamic_whitelist
        else:
            white_content += _read_file(DYNAMIC_WHITELIST_FILE)

        domains = set(convert_to_allow_list(white_content))
        if extra_domains:
            domains |= extra_domains
            info(
                f"Added {len(extra_domains)} auto-whitelisted "
                f"@@|| exceptions to the Allow list"
            )
        return sorted(domains)


def _read_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")
