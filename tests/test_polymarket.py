"""Regression tests for the read-only Polymarket example."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from examples import polymarket_server


def _use_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    """Route the example's async HTTP client through a local fake transport."""
    async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return async_client(*args, **kwargs)

    monkeypatch.setattr(polymarket_server.httpx, "AsyncClient", client_factory)


def test_search_markets_uses_public_search_and_maps_named_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_request
        seen_request = request
        return httpx.Response(
            200,
            json={
                "events": [
                    {
                        "title": "Bitcoin price in 2026",
                        "slug": "bitcoin-price-in-2026",
                        "markets": [
                            {
                                "question": "Will Bitcoin exceed $150k in 2026?",
                                "slug": "will-bitcoin-exceed-150k-in-2026",
                                "outcomes": '["No", "Yes"]',
                                "outcomePrices": '["0.35", "0.65"]',
                                "volume24hr": 1250.5,
                                "liquidity": "9876.25",
                                "endDate": "2026-12-31T23:59:59Z",
                            },
                            {
                                "question": "Will Bitcoin exceed $200k in 2026?",
                                "slug": "will-bitcoin-exceed-200k-in-2026",
                                "outcomes": '["Yes", "No"]',
                                "outcomePrices": '["0.2", "0.8"]',
                            },
                        ],
                    }
                ],
                "pagination": {"hasMore": True, "totalResults": 12},
            },
        )

    _use_mock_transport(monkeypatch, handler)

    result = asyncio.run(polymarket_server.search_markets("bitcoin", limit=1, page=2))

    assert seen_request is not None
    assert seen_request.method == "GET"
    assert seen_request.url.path == "/public-search"
    assert dict(seen_request.url.params) == {
        "q": "bitcoin",
        "events_status": "active",
        "limit_per_type": "1",
        "page": "2",
        "search_profiles": "false",
        "search_tags": "false",
    }
    assert result == [
        {
            "question": "Will Bitcoin exceed $150k in 2026?",
            "slug": "will-bitcoin-exceed-150k-in-2026",
            "outcome_prices": {"No": 0.35, "Yes": 0.65},
            "volume_24h": 1250.5,
            "liquidity": "9876.25",
            "end_date": "2026-12-31T23:59:59Z",
            "event": "Bitcoin price in 2026",
            "url": "https://polymarket.com/event/bitcoin-price-in-2026",
        }
    ]


@pytest.mark.parametrize("events", [[], None])
def test_search_markets_returns_empty_list_for_no_matching_events(
    monkeypatch: pytest.MonkeyPatch, events: list[object] | None
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200, json={"events": events, "pagination": {"hasMore": False}}
        ),
    )

    assert asyncio.run(polymarket_server.search_markets("no matches")) == []


def test_search_markets_skips_events_without_usable_markets_or_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "events": [
                    {"title": "No markets key"},
                    {"title": "Empty markets", "slug": "empty", "markets": []},
                    {
                        "title": "Missing slug",
                        "markets": [{"question": "Q", "slug": "orphan"}],
                    },
                    {
                        "title": "Usable",
                        "slug": "usable-event",
                        "markets": [
                            {
                                "question": "Will it resolve?",
                                "slug": "will-it-resolve",
                                "outcomes": '["Yes", "No"]',
                                "outcomePrices": '["0.5", "0.5"]',
                            }
                        ],
                    },
                ]
            },
        ),
    )

    result = asyncio.run(polymarket_server.search_markets("bitcoin"))

    assert [market["slug"] for market in result] == ["will-it-resolve"]


def test_search_markets_skips_incomplete_markets_and_keeps_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "events": [
                    {
                        "title": "Mixed event",
                        "slug": "mixed-event",
                        "markets": [
                            {
                                "slug": "missing-question",
                                "outcomes": '["Yes", "No"]',
                                "outcomePrices": '["0.5", "0.5"]',
                            },
                            {"question": "Missing slug?", "outcomes": '["Yes"]'},
                            {
                                "question": "Missing prices?",
                                "slug": "missing-prices",
                                "outcomes": '["Yes", "No"]',
                            },
                            {
                                "question": "Mismatched lengths?",
                                "slug": "mismatched-lengths",
                                "outcomes": '["Yes", "No"]',
                                "outcomePrices": '["0.5"]',
                            },
                            {
                                "question": "Will it resolve?",
                                "slug": "will-it-resolve",
                                "outcomes": '["Yes", "No"]',
                                "outcomePrices": '["0.4", "0.6"]',
                            },
                        ],
                    }
                ]
            },
        ),
    )

    result = asyncio.run(polymarket_server.search_markets("bitcoin"))

    assert result == [
        {
            "question": "Will it resolve?",
            "slug": "will-it-resolve",
            "outcome_prices": {"Yes": 0.4, "No": 0.6},
            "volume_24h": None,
            "liquidity": None,
            "end_date": None,
            "event": "Mixed event",
            "url": "https://polymarket.com/event/mixed-event",
        }
    ]


def test_get_market_by_slug_still_rejects_an_incomplete_market(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "slug": "missing-question",
                "outcomes": '["Yes", "No"]',
                "outcomePrices": '["0.5", "0.5"]',
                "events": [{"title": "Parent", "slug": "parent-event"}],
            },
        ),
    )

    with pytest.raises(ValueError, match="missing question"):
        asyncio.run(polymarket_server.get_market_by_slug("missing-question"))


@pytest.mark.parametrize("limit", [0, 101])
def test_search_markets_rejects_out_of_range_limits(
    monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    def unexpected_request(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"invalid input made an upstream request: {request.url}")

    _use_mock_transport(monkeypatch, unexpected_request)

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        asyncio.run(polymarket_server.search_markets("bitcoin", limit=limit))


def test_search_markets_rejects_malformed_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(200, json={"events": {"not": "a list"}}),
    )

    with pytest.raises(ValueError, match="events must be a list"):
        asyncio.run(polymarket_server.search_markets("bitcoin"))


def test_get_market_by_slug_uses_slug_endpoint_and_event_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_request
        seen_request = request
        return httpx.Response(
            200,
            json={
                "question": "Which party wins?",
                "slug": "which-party-wins",
                "outcomes": '["Party B", "Party A"]',
                "outcomePrices": '["0.4", "0.6"]',
                "volume": "10000",
                "volume24hr": 150,
                "liquidity": "2500",
                "endDate": "2026-11-04T00:00:00Z",
                "active": True,
                "closed": False,
                "events": [{"slug": "national-election", "title": "Election"}],
            },
        )

    _use_mock_transport(monkeypatch, handler)

    result = asyncio.run(polymarket_server.get_market_by_slug("which-party-wins"))

    assert seen_request is not None
    assert seen_request.url.path == "/markets/slug/which-party-wins"
    assert result == {
        "question": "Which party wins?",
        "slug": "which-party-wins",
        "outcome_prices": {"Party B": 0.4, "Party A": 0.6},
        "volume": "10000",
        "volume_24h": 150,
        "liquidity": "2500",
        "end_date": "2026-11-04T00:00:00Z",
        "active": True,
        "closed": False,
        "event": "Election",
        "url": "https://polymarket.com/event/national-election",
    }


def test_get_market_by_slug_rejects_mismatched_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "question": "Broken market",
                "slug": "broken",
                "outcomes": '["Yes", "No"]',
                "outcomePrices": '["0.5"]',
                "events": [{"slug": "broken-event"}],
            },
        ),
    )

    with pytest.raises(ValueError, match="same number of entries"):
        asyncio.run(polymarket_server.get_market_by_slug("broken"))


def test_upstream_http_errors_are_not_silently_converted_to_empty_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(503, json={"error": "unavailable"}),
    )

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(polymarket_server.search_markets("bitcoin"))


def test_build_app_is_explicit_and_registers_only_polymarket_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    expected_app = object()

    monkeypatch.setattr(polymarket_server, "auth_from_env", lambda: None)

    def fake_create_app(
        mcp: Any, *, allow_anonymous: bool = False, cors_origins: Any = None
    ) -> object:
        captured["mcp"] = mcp
        captured["allow_anonymous"] = allow_anonymous
        return expected_app

    monkeypatch.setattr(polymarket_server, "create_app", fake_create_app)

    assert not hasattr(polymarket_server, "app")
    assert polymarket_server.build_app() is expected_app
    assert captured["allow_anonymous"] is True
    tools = asyncio.run(captured["mcp"].list_tools())
    assert {tool.name for tool in tools} == {"search_markets", "get_market_by_slug"}
