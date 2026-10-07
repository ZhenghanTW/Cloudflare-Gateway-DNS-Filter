"""Project configuration: paths, constants, regexes and credentials.

Everything that used to live in ``src/__init__.py`` is collected here so the
package's ``__init__`` stays side-effect free and importing submodules does
not require Cloudflare credentials to be present.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

LISTS_DIR = PROJECT_ROOT / "lists"
ADLIST_FILE = LISTS_DIR / "adlist.ini"
WHITELIST_FILE = LISTS_DIR / "whitelist.ini"
DYNAMIC_BLACKLIST_FILE = LISTS_DIR / "dynamic_blacklist.txt"
DYNAMIC_WHITELIST_FILE = LISTS_DIR / "dynamic_whitelist.txt"
CACHE_FILE = PROJECT_ROOT / "cloudflare_cache.json"

# Cloudflare Gateway free tier hard limit for the number of lists.
MAX_TOTAL_LISTS = 300
DOMAINS_PER_LIST = 1000

# Suffixes used to name the Cloudflare resources this project manages.
BLOCK_PREFIX = "AdBlock-DNS-Filters"
ALLOW_PREFIX = "AdAllow-DNS-Filters"

CLOUDFLARE_HOST = "api.cloudflare.com"
CLOUDFLARE_API_PATH = "/client/v4/accounts/{account_id}/gateway"

# SNI-based (network/L4) filtering is opt-in: it requires the device to be
# connected through the Cloudflare WARP client with the TCP proxy enabled.
# Without that, this rule has no effect, so we don't create it by default.
ENABLE_SNI_FILTER = (os.getenv("ENABLE_SNI_FILTER") or "").strip().lower() in (
    "1",
    "true",
    "yes",
)

_PLACEHOLDER_TOKEN = "your CF_API_TOKEN value"
_PLACEHOLDER_IDENTIFIER = "your CF_IDENTIFIER value"


class ConfigError(Exception):
    """Raised when required configuration (Cloudflare credentials) is missing."""


def load_dotenv(path: Path = ENV_FILE) -> dict[str, str]:
    """Parse a minimal ``.env`` file into a mapping.

    Supports ``KEY=value`` lines, optional ``export`` prefixes, surrounding
    single/double quotes and the ``<placeholder>`` form used by the sample
    ``.env``. This intentionally avoids a third-party dependency.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if len(value) >= 2 and value.startswith("<") and value.endswith(">"):
            value = value[1:-1]
        if key:
            values[key] = value

    return values


_DOTENV = load_dotenv()


def _get(name: str) -> Optional[str]:
    return os.getenv(name) or _DOTENV.get(name)


CF_API_TOKEN = _get("CF_API_TOKEN")
CF_IDENTIFIER = _get("CF_IDENTIFIER")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")


def require_credentials() -> None:
    """Validate that Cloudflare credentials are configured.

    Called explicitly by the CLI instead of at import time so tools such as
    ``python -m cloudflare_gateway --help`` keep working without secrets.
    """
    if (
        not CF_API_TOKEN
        or CF_API_TOKEN == _PLACEHOLDER_TOKEN
        or not CF_IDENTIFIER
        or CF_IDENTIFIER == _PLACEHOLDER_IDENTIFIER
    ):
        raise ConfigError(
            "Missing Cloudflare credentials. Set CF_API_TOKEN and CF_IDENTIFIER "
            "as environment variables or in the .env file."
        )


# Regex patterns shared by the list converters.
IDS_PATTERN = re.compile(r"\$([a-f0-9-]+)")
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3,4}$")
REPLACE_PATTERN = re.compile(r"(^([0-9.]+|[0-9a-fA-F:.]+)\s+|^(\|\||@@\|\||\*\.|\*))")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)
