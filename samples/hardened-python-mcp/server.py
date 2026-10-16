"""Inventory MCP server: read-only access to the product catalogue.

Runs as a stateless Streamable HTTP service behind the corporate gateway.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import httpx
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field
from tenacity import retry, stop_after_attempt, wait_exponential

from .auth import IntrospectionVerifier

log = logging.getLogger("inventory_mcp")

CATALOG_URL = os.environ["CATALOG_URL"]
MAX_ROWS = 200


@asynccontextmanager
async def lifespan(app):
    app.http = httpx.AsyncClient(base_url=CATALOG_URL, timeout=httpx.Timeout(10.0, connect=3.0),
                                 limits=httpx.Limits(max_connections=100))
    yield
    await app.http.aclose()


mcp = FastMCP(
    "inventory",
    stateless_http=True,
    json_response=True,
    token_verifier=IntrospectionVerifier(),
    auth=AuthSettings(issuer_url=os.environ["ISSUER_URL"], resource_server_url=os.environ["RESOURCE_URL"], required_scopes=["inventory.read"]),
    lifespan=lifespan,
)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.2, max=2))
async def _get(client: httpx.AsyncClient, path: str, params: dict) -> dict:
    r = await client.get(path, params=params)
    r.raise_for_status()
    return r.json()


@mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False})
async def search_products(
    ctx: Context,
    text: Annotated[str, Field(description="Free-text search on product name", max_length=120)],
    category: Annotated[Literal["hardware", "software", "services"], Field(description="Product family")] = "hardware",
    limit: Annotated[int, Field(ge=1, le=MAX_ROWS, description="Maximum rows to return")] = 50,
) -> dict:
    """Search the product catalogue by name within one category.

    Returns at most `limit` products (id, name, price, stock) and a `truncated` flag.
    """
    log.info("tool_call", extra={"tool": "search_products", "category": category, "limit": limit})
    data = await _get(ctx.request_context.lifespan_context.http, "/products", {"q": text, "cat": category, "limit": limit + 1})
    items = data.get("items", [])
    return {"items": items[:limit], "truncated": len(items) > limit}


@mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False})
async def get_product(ctx: Context, product_id: Annotated[str, Field(pattern=r"^P-\d{6}$", description="Product id, e.g. P-000123")]) -> dict:
    """Return one product with stock per warehouse. Use search_products first to find the id."""
    log.info("tool_call", extra={"tool": "get_product", "product_id": product_id})
    return await _get(ctx.request_context.lifespan_context.http, f"/products/{product_id}", {})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="streamable-http")
