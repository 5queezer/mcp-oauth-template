"""Read-only Polymarket market search MCP server.

The tools use Polymarket's public Gamma API and do not place trades or require
Polymarket credentials. Set ``MCP_AUTH_MODE=demo`` for an explicit local demo;
the default server mode requires the GitHub OAuth configuration documented by
the project.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Annotated, Any, cast
from urllib.parse import quote

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from pydantic import Field
from starlette.applications import Starlette

from mcp_server import create_app
from mcp_server.auth import auth_from_env

GAMMA_API = "https://gamma-api.polymarket.com"
POLYMARKET_EVENT_URL = "https://polymarket.com/event"
REQUEST_TIMEOUT_SECONDS = 10.0

SearchLimit = Annotated[
    int,
    Field(ge=1, le=100, description="Maximum number of markets to return"),
]
SearchPage = Annotated[int, Field(ge=1, description="One-based search result page")]
SearchQuery = Annotated[str, Field(min_length=1, description="Market search text")]
MarketSlug = Annotated[str, Field(min_length=1, description="Exact Polymarket market slug")]


async def _get_gamma(
    path: str,
    *,
    params: dict[str, str | int | bool] | None = None,
) -> Any:
    async with httpx.AsyncClient(
        base_url=GAMMA_API,
        timeout=REQUEST_TIMEOUT_SECONDS,
    ) as client:
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response.json()


def _decoded_list(raw: object, field_name: str) -> list[object]:
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Polymarket {field_name} is not valid JSON") from exc
    else:
        value = raw

    if not isinstance(value, list):
        raise ValueError(f"Polymarket {field_name} must be a list")
    return cast("list[object]", value)


def _outcome_prices(market: Mapping[str, object]) -> dict[str, float]:
    outcomes = _decoded_list(market.get("outcomes"), "outcomes")
    prices = _decoded_list(market.get("outcomePrices"), "outcomePrices")
    if len(outcomes) != len(prices):
        raise ValueError(
            "Polymarket outcomes and outcomePrices must contain the same number of entries"
        )

    result: dict[str, float] = {}
    for outcome, raw_price in zip(outcomes, prices, strict=True):
        if not isinstance(outcome, str) or not outcome.strip():
            raise ValueError("Polymarket outcomes must contain nonempty names")
        if outcome in result:
            raise ValueError(f"Polymarket returned a duplicate outcome: {outcome}")
        if isinstance(raw_price, bool) or not isinstance(raw_price, str | int | float):
            raise ValueError(f"Polymarket returned an invalid price for {outcome}")
        try:
            price = float(raw_price)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Polymarket returned an invalid price for {outcome}") from exc
        if not math.isfinite(price):
            raise ValueError(f"Polymarket returned a non-finite price for {outcome}")
        result[outcome] = price
    return result


def _required_text(record: Mapping[str, object], field_name: str) -> str:
    value = record.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Polymarket result is missing {field_name}")
    return value


def _market_summary(
    market: Mapping[str, object],
    *,
    event_title: object,
    event_slug: str,
) -> dict[str, object]:
    return {
        "question": _required_text(market, "question"),
        "slug": _required_text(market, "slug"),
        "outcome_prices": _outcome_prices(market),
        "volume_24h": market.get("volume24hr"),
        "liquidity": market.get("liquidity"),
        "end_date": market.get("endDate"),
        "event": event_title,
        "url": f"{POLYMARKET_EVENT_URL}/{quote(event_slug, safe='')}",
    }


async def search_markets(
    query: SearchQuery,
    limit: SearchLimit = 20,
    page: SearchPage = 1,
) -> list[dict[str, object]]:
    """Search active Polymarket events and return their markets.

    ``page`` follows the Gamma search endpoint's one-based pagination. Use the
    next page when the desired market is not present in a bounded result set.
    """
    query = query.strip()
    if not query:
        raise ValueError("query must not be empty")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if page < 1:
        raise ValueError("page must be at least 1")

    payload = await _get_gamma(
        "/public-search",
        params={
            "q": query,
            "events_status": "active",
            "limit_per_type": limit,
            "page": page,
            "search_profiles": False,
            "search_tags": False,
        },
    )
    if not isinstance(payload, Mapping):
        raise ValueError("Polymarket search response must be an object")

    events = payload.get("events")
    if events is None:
        return []
    if not isinstance(events, list):
        raise ValueError("Polymarket search response events must be a list")

    results: list[dict[str, object]] = []
    for event in events:
        if not isinstance(event, Mapping):
            raise ValueError("Polymarket search response contains an invalid event")
        # /public-search returns heterogeneous records. An event without usable
        # markets or without a slug is ordinary upstream output, so it is
        # skipped rather than failing the whole search.
        markets = event.get("markets")
        if not isinstance(markets, list) or not markets:
            continue
        try:
            event_slug = _required_text(event, "slug")
        except ValueError:
            continue
        for market in markets:
            if not isinstance(market, Mapping):
                raise ValueError("Polymarket event contains an invalid market")
            results.append(
                _market_summary(
                    market,
                    event_title=event.get("title"),
                    event_slug=event_slug,
                )
            )
            if len(results) == limit:
                return results
    return results


async def get_market_by_slug(slug: MarketSlug) -> dict[str, object]:
    """Fetch one market by its exact Gamma API slug."""
    slug = slug.strip()
    if not slug:
        raise ValueError("slug must not be empty")

    payload = await _get_gamma(f"/markets/slug/{quote(slug, safe='')}")
    if not isinstance(payload, Mapping):
        raise ValueError("Polymarket market response must be an object")

    events = payload.get("events")
    if not isinstance(events, list) or not events or not isinstance(events[0], Mapping):
        raise ValueError("Polymarket market response is missing its parent event")
    event = events[0]
    event_slug = _required_text(event, "slug")

    result = _market_summary(
        payload,
        event_title=event.get("title"),
        event_slug=event_slug,
    )
    return {
        **result,
        "volume": payload.get("volume"),
        "active": payload.get("active"),
        "closed": payload.get("closed"),
    }


def _new_server(auth: AuthProvider | None) -> FastMCP:
    server = FastMCP(
        "polymarket",
        instructions=(
            "Search live Polymarket prediction markets and inspect a market by slug. "
            "These tools are read-only and never place trades."
        ),
        auth=auth,
    )
    server.tool()(search_markets)
    server.tool()(get_market_by_slug)
    return server


def build_app() -> Starlette:
    """Build the ASGI application from the current authentication environment."""
    auth = auth_from_env()
    server = _new_server(auth)
    return create_app(server, allow_anonymous=auth is None)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(build_app(), host="0.0.0.0", port=8080, log_level="info")
