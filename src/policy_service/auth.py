"""Trusted IAM context policy-service.

Decision API принимает только audience-bound access token iam-service
(`platform-auth-sdk`). Principal и tenant берутся из проверенных claims;
`principalId` в теле запроса допускается лишь при scope
`policy:check-on-behalf` — так resource servers спрашивают за конечного
пользователя. Admin API в v0 закрыт bootstrap-заголовком либо токеном со
scope `policy:admin` того же tenant.
"""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import InvalidToken, VerificationUnavailable
from platform_auth.jwks import JwksCache, StaticKeySet
from platform_auth.verify import KeySource, TokenVerifier, VerifierConfig

SCOPE_CHECK = "policy:check"
SCOPE_ON_BEHALF = "policy:check-on-behalf"
SCOPE_ADMIN = "policy:admin"
BOOTSTRAP_HEADER = "X-Policy-Bootstrap-Token"


class IamContextError(Exception):
    """Token отсутствует, повреждён или не относится к нашему audience."""


class IamVerificationUnavailable(Exception):
    """Ключ проверки не сконфигурирован или недоступен: отвечать deny, не allow."""


@dataclass(frozen=True)
class AuthContext:
    tenant_id: uuid.UUID
    principal_id: uuid.UUID
    principal_type: str
    scopes: frozenset[str]
    credential_id: str
    correlation_id: str = ""

    def may_act_on_behalf(self) -> bool:
        return SCOPE_ON_BEHALF in self.scopes

    def is_admin(self) -> bool:
        return SCOPE_ADMIN in self.scopes

    def resolve_principal(self, requested: str | None) -> str:
        """Principal решения: свой из токена, чужой — только с on-behalf scope."""
        own = str(self.principal_id)
        if not requested or requested == own:
            return own
        if not self.may_act_on_behalf():
            raise IamContextError("principal_not_allowed")
        return requested

    @classmethod
    def from_trusted(cls, ctx: TrustedAuthContext) -> AuthContext:
        return cls(
            tenant_id=ctx.tenant_id,
            principal_id=ctx.principal_id,
            principal_type=ctx.principal_type,
            scopes=ctx.effective_scopes(),
            credential_id=ctx.credential_id,
            correlation_id=ctx.correlation_id,
        )


class IamContextVerifier:
    def __init__(self, *, issuer: str, audience: str, public_key_pem: str, jwks_url: str) -> None:
        keys: KeySource | None = None
        if public_key_pem:
            keys = StaticKeySet(public_key_pem)
        elif jwks_url:
            keys = JwksCache(jwks_url)
        self._verifier: TokenVerifier | None = None
        if keys is not None and issuer and audience:
            self._verifier = TokenVerifier(keys, VerifierConfig(issuer=issuer, audience=audience))

    async def verify(self, token: str, *, correlation_id: str = "") -> AuthContext:
        if self._verifier is None:
            raise IamVerificationUnavailable("iam_verifier_not_configured")
        if not token:
            raise IamContextError("missing_token")
        try:
            trusted = await self._verifier.verify(token, correlation_id=correlation_id)
        except InvalidToken as exc:
            raise IamContextError(exc.audit_reason) from exc
        except VerificationUnavailable as exc:
            raise IamVerificationUnavailable(exc.audit_reason) from exc
        return AuthContext.from_trusted(trusted)


def bootstrap_token_matches(expected: str, presented: str | None) -> bool:
    if not expected or not presented:
        return False
    return hmac.compare_digest(expected.encode(), presented.encode())
