from mcp.server.auth.provider import AccessToken, TokenVerifier


class IntrospectionVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        ...
