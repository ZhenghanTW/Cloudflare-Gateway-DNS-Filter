"""Minimal GitHub REST API client used for workflow/cache housekeeping."""

from __future__ import annotations

from typing import Optional

from .config import GITHUB_REPOSITORY, GITHUB_TOKEN
from .http_client import HTTPException, get_session


class GithubAPI:
    """Small wrapper around the GitHub REST API."""

    BASE_URL = "https://api.github.com"

    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0",
        }

    @classmethod
    def request(cls, method: str, path: str, body: Optional[str] = None) -> dict:
        url = f"{cls.BASE_URL}{path}"
        response = get_session().request(
            method, url, body=body, headers=cls._headers(), timeout=20
        )
        if response.status_code >= 400:
            raise HTTPException(
                f"GitHub API request failed: {response.status_code} {response.reason} "
                f"for {method} {url}: {response.text}",
                method=method,
                url=url,
                status_code=response.status_code,
                reason=response.reason,
                body=response.text,
            )
        return response.json() if response.content else {}

    @classmethod
    def get(cls, path: str) -> dict:
        return cls.request("GET", path)

    @classmethod
    def delete(cls, path: str) -> dict:
        return cls.request("DELETE", path)

    @staticmethod
    def repository() -> Optional[str]:
        return GITHUB_REPOSITORY
