"""
Polymarket MCP Server -- built on mcp-oauth-template.

Deploy to Cloud Run:
  gcloud run deploy polymarket-mcp \
    --source . \
    --region europe-west1 \
    --set-env-vars BASE_URL=https://polymarket-mcp-xxxx.run.app

Then add as MCP connector in claude.ai:
  URL: https://polymarket-mcp-xxxx.run.app/mcp
"""

import json
import os

import httpx
import fastmcp
from mcp_server import create_app, StaticPasswordProvider

# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

mcp = fastmcp.FastMCP(
    "polymarket",
    instructions=(
        "Query live Polymarket prediction markets. "
        "Use get_hormuz_markets() for Iran/Hormuz/oil thesis markets, "
        "search_markets(keyword) to find any topic, "
        "get_market_by_slug(slug) for a specific market by its URL slug."
    ),
)

GAMMA_API = "https://gamma-api.polymarket.com"
HORMUZ_KEYWORDS = ["iran", "hormuz", "wti", "oil", "militar", "sanction", "crude"]


@mcp.tool()
def get_hormuz_markets() -> list[dict]:
    """
    Fetch active Polymarket markets relevant to the Hormuz thesis.
    Filters by keywords: Iran, WTI, oil, military, sanctions.
    """
    with httpx.Client(timeout=10) as client:
        resp = client.get(
            f"{GAMMA_API}/markets",
            params={"active": "true", "closed": "false", "limit": 100},
        )
        resp.raise_for_status()
        markets = resp.json()

    results = []
    for m in markets:
        question = (m.get("question") or "").lower()
        if any(kw in question for kw in HORMUZ_KEYWORDS):
            prices = _parse_prices(m.get("outcomePrices", "[]"))
            results.append({
                "question": m.get("question"),
                "yes_price": prices[0] if prices else None,
                "no_price": prices[1] if len(prices) > 1 else None,
                "volume_24h": m.get("volume24hr"),
                "liquidity": m.get("liquidity"),
                "end_date": m.get("endDate"),
                "url": f"https://polymarket.com/market/{m.get('slug', '')}",
            })

    return sorted(results, key=lambda x: x["volume_24h"] or 0, reverse=True)


@mcp.tool()
def search_markets(keyword: str, limit: int = 20) -> list[dict]:
    """
    Search active Polymarket markets by keyword.

    Args:
        keyword: Search term (e.g. 'fed rate', 'bitcoin', 'election')
        limit:   Max results (default 20)
    """
    with httpx.Client(timeout=10) as client:
        resp = client.get(
            f"{GAMMA_API}/markets",
            params={"active": "true", "closed": "false", "limit": 200},
        )
        resp.raise_for_status()
        markets = resp.json()

    kw = keyword.lower()
    results = []
    for m in markets:
        if kw in (m.get("question") or "").lower():
            prices = _parse_prices(m.get("outcomePrices", "[]"))
            results.append({
                "question": m.get("question"),
                "yes_price": prices[0] if prices else None,
                "no_price": prices[1] if len(prices) > 1 else None,
                "volume_24h": m.get("volume24hr"),
                "end_date": m.get("endDate"),
            })
            if len(results) >= limit:
                break

    return results


@mcp.tool()
def get_market_by_slug(slug: str) -> dict:
    """
    Fetch a specific Polymarket market by its slug.
    Slug is the URL path after /market/ on polymarket.com.

    Args:
        slug: e.g. 'will-wti-hit-120-in-april-2026'
    """
    with httpx.Client(timeout=10) as client:
        resp = client.get(f"{GAMMA_API}/markets", params={"slug": slug})
        resp.raise_for_status()
        data = resp.json()

    if not data:
        return {"error": f"No market found for slug: {slug}"}

    m = data[0]
    prices = _parse_prices(m.get("outcomePrices", "[]"))
    return {
        "question": m.get("question"),
        "yes_price": prices[0] if prices else None,
        "no_price": prices[1] if len(prices) > 1 else None,
        "volume": m.get("volume"),
        "volume_24h": m.get("volume24hr"),
        "liquidity": m.get("liquidity"),
        "end_date": m.get("endDate"),
        "active": m.get("active"),
        "closed": m.get("closed"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_prices(raw: str) -> list[float]:
    try:
        return [float(p) for p in json.loads(raw)]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = create_app(
    mcp=mcp,
    # Remove StaticPasswordProvider to use SingleUserProvider (no login)
    # provider=StaticPasswordProvider(os.environ["ADMIN_PASSWORD"]),
    title="Polymarket MCP",
)

# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
