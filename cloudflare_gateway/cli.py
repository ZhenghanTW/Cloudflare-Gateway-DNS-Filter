"""Command-line entry point for the Cloudflare Gateway DNS filter."""

from __future__ import annotations

import argparse
from typing import Optional, Sequence

from . import state
from .config import ConfigError, require_credentials
from .log import fatal
from .manager import CloudflareManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudflare_gateway",
        description="Cloudflare Gateway DNS Filter Manager (Block + Allow)",
    )
    parser.add_argument(
        "action",
        choices=("run", "leave"),
        help="run: sync resources | leave: delete all resources",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI. Returns a process exit code."""
    args = build_parser().parse_args(argv)

    try:
        require_credentials()
    except ConfigError as exc:
        fatal(str(exc))

    cache = state.load_cache()
    manager = CloudflareManager(cache)

    if args.action == "run":
        manager.update_resources()
        if state.is_running_in_github_actions():
            state.delete_cache()
    else:
        manager.delete_resources()

    return 0
