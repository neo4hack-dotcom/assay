# Inventory MCP

Read-only access to the product catalogue for agents.

## Tools
- `search_products` — search by name within a category (max 200 rows, truncated flag).
- `get_product` — one product by id.

## Configuration
| Variable | Purpose |
|---|---|
| CATALOG_URL | Catalogue API base URL |
| ISSUER_URL | OAuth issuer |
| RESOURCE_URL | This server's canonical resource URI (audience) |

## Operations
Stateless Streamable HTTP; scale horizontally behind the gateway. Health: `/health` on the gateway.
Rate limiting: gateway policy 50 rps per client. Logs are JSON; traces via OpenTelemetry.
