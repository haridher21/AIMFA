"""DPoP proofs (RFC 9449, simplified): prove that the caller holds the agent's private key.

An access token alone is a bearer secret: whoever steals it can use it. DPoP binds the
token to a key pair. On every request the agent signs a tiny, single-use JWT (the
"proof") that names the HTTP method and URL, the current time, a random ``jti`` and a
hash of the access token. A thief who copies the token (or an old proof) cannot make a
new valid proof without the private key.

``verify_proof`` runs the checks in a fixed order and raises ``DPoPError`` with the first
failing ``ReasonCode``:

    MALFORMED -> BAD_SIGNATURE -> KEY_MISMATCH -> HTM -> HTU -> STALE -> ATH -> REPLAY

Nothing a proof claims is trusted until its signature checks out, and its ``jti`` is
recorded in the replay cache only after every other check passed, so a forged or
broken proof can never "use up" a victim's ``jti``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import hmac
import json
import re
import secrets
import threading
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from aimfa.common.crypto import jwk_thumbprint, public_jwk, sign_jwt
from aimfa.common.models import SIGNING_ALG, DPoPProofClaims, PublicJWK, ReasonCode

__all__ = [
    "DPOP_TYP",
    "MAX_PROOF_LENGTH",
    "DPoPError",
    "ReplayCache",
    "access_token_hash",
    "make_proof",
    "verify_proof",
]

DPOP_TYP = "dpop+jwt"

# DoS guard: a real proof is a few hundred characters. Refusing huge inputs up front
# means an attacker cannot make us base64-decode, JSON-parse and verify megabytes.
MAX_PROOF_LENGTH = 8192

# The only header members a proof may carry. Anything else (``crit``, ``b64``, ``kid``,
# ``x5u``, ``jku`` ...) is an extension we do not implement, so it is refused.
_ALLOWED_HEADER_MEMBERS = frozenset({"typ", "alg", "jwk"})
# The only JWK members allowed: the public Ed25519 key and an optional label. ``d`` (the
# private key) or anything pointing elsewhere (``x5u``) is refused.
_ALLOWED_JWK_MEMBERS = frozenset({"kty", "crv", "x", "kid"})

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")

# Options for the signature-only verification. A proof has no aud/iss/exp, so those
# checks are off; freshness, jti and every other claim are checked by us afterwards,
# with an injected clock. The signature check itself is never disabled.
_SIGNATURE_ONLY_OPTIONS: dict[str, Any] = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
    "verify_aud": False,
    "verify_iss": False,
    "verify_sub": False,
    "verify_jti": False,
    "require": [],
}


class DPoPError(Exception):
    """A DPoP proof was rejected. ``reason_code`` says why.

    The message is only the reason code, never the proof, token or key, so logging this
    exception cannot leak a secret.
    """

    def __init__(self, reason_code: ReasonCode) -> None:
        self.reason_code = ReasonCode(reason_code)
        super().__init__(self.reason_code.value)


# ------------------------------------------------------------------ replay cache


class ReplayCache:
    """Remembers ``jti`` values of accepted proofs so each proof works only once.

    Entries live for TTL = 2 x ``max_age``: a proof dated up to ``max_age`` in the future
    and first seen now stays fresh until ``now + 2 * max_age``, and the cache must still
    remember it at that moment. Time comes from the caller (injected clock), so tests
    and the verifier agree on "now". Thread-safe: check-and-insert happens under one lock,
    so two simultaneous copies of one proof cannot both succeed.
    """

    def __init__(self, max_age: int) -> None:
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
            raise ValueError("max_age must be a positive integer number of seconds")
        self.max_age = max_age
        self.ttl = 2 * max_age
        self._lock = threading.Lock()
        self._expires: dict[str, int] = {}
        self._heap: list[tuple[int, str]] = []  # (expiry, jti), for cheap pruning

    def check_and_store(self, jti: str, now: int, fresh_until: int) -> bool:
        """Record ``jti``; return False if it was already recorded (a replay).

        The entry is kept until ``max(now + ttl, fresh_until)``, so even if the verifier
        was given a larger ``max_age`` than this cache, a proof is remembered for as long
        as it could still pass the freshness check.
        """
        expiry = max(now + self.ttl, fresh_until)
        with self._lock:
            self._prune(now)
            if jti in self._expires:
                return False
            self._expires[jti] = expiry
            heapq.heappush(self._heap, (expiry, jti))
            return True

    def _prune(self, now: int) -> None:
        """Drop expired entries (caller holds the lock) so memory does not grow forever."""
        while self._heap and self._heap[0][0] < now:
            expiry, jti = heapq.heappop(self._heap)
            if self._expires.get(jti) == expiry:
                del self._expires[jti]

    def __len__(self) -> int:
        with self._lock:
            return len(self._expires)


# ------------------------------------------------------------------ small pure helpers


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    """Strict base64url decode: only the URL-safe alphabet, no padding, valid length.

    ``base64`` alone silently skips junk characters; we refuse them so two different
    strings cannot decode to the same bytes in surprising ways.
    """
    if not _B64URL_RE.fullmatch(segment) or len(segment) % 4 == 1:
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not base64url") from None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Duplicate JSON keys are refused: parsers disagree on which copy wins, and that
    disagreement is a classic way to make the checker and the user see different values."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate JSON member")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _strict_json_object(data: bytes) -> dict[str, Any]:
    """Parse UTF-8 JSON that must be an object (no NaN/Infinity, no duplicate keys)."""
    try:
        obj = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("not a JSON object") from None
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    return obj


def _ct_equal(a: str, b: str) -> bool:
    """Constant-time string compare (AGENTS.md rule 3).

    ``hmac.compare_digest`` refuses non-ASCII ``str``, so compare UTF-8 bytes instead;
    an attacker-supplied non-ASCII value then simply does not match (no crash).
    """
    return hmac.compare_digest(
        a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass")
    )


def access_token_hash(access_token: str) -> str:
    """``ath`` value: base64url(SHA-256(ASCII bytes of the token)), RFC 9449 section 4.2.

    Raises ``ValueError`` for a non-ASCII token (real tokens are always ASCII).
    """
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def _has_query_or_fragment(url: str) -> bool:
    """RFC 9449: ``htu`` is the URL *without* query and fragment."""
    return "?" in url or "#" in url


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else int(now)


# ------------------------------------------------------------------ make_proof


def make_proof(
    private_key: Ed25519PrivateKey,
    htm: str,
    htu: str,
    access_token: str | None = None,
    now: int | None = None,
) -> str:
    """Create a DPoP proof for one request (client side).

    The header carries only the *public* key; the private key signs. ``jti`` comes from
    ``secrets`` so it cannot be guessed. ``ath`` (a hash, never the token itself) is
    added when an access token is sent with the request.
    """
    if not isinstance(htm, str) or not htm:
        raise ValueError("htm must be a non-empty string")
    if not isinstance(htu, str) or not htu or _has_query_or_fragment(htu):
        raise ValueError("htu must be a non-empty URL without query or fragment")
    claims: dict[str, Any] = {
        "jti": secrets.token_urlsafe(24),
        "htm": htm,
        "htu": htu,
        "iat": _now(now),
    }
    if access_token is not None:
        claims["ath"] = access_token_hash(access_token)
    jwk = public_jwk(private_key).model_dump(exclude_none=True)
    return sign_jwt(claims, private_key, headers={"typ": DPOP_TYP, "jwk": jwk})


# ------------------------------------------------------------------ verify_proof steps


def _parse_header(proof: Any) -> tuple[PublicJWK, Ed25519PublicKey, str]:
    """Structural checks done before any crypto. Raises DPOP_MALFORMED.

    ``typ`` and ``alg`` are compared exactly: ``typ`` stops an ordinary JWT (e.g. an
    access token) from being accepted as a proof, and pinning ``alg`` stops the
    ``alg=none`` and HS256-with-the-public-key tricks. ``kty``/``crv`` must really be
    present, because ``PublicJWK`` would otherwise fill them in with defaults.
    """
    malformed = DPoPError(ReasonCode.DPOP_MALFORMED)
    if not isinstance(proof, str) or not proof or len(proof) > MAX_PROOF_LENGTH:
        raise malformed
    parts = proof.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise malformed
    if not _B64URL_RE.fullmatch(parts[2]):
        raise malformed
    try:
        header = _strict_json_object(_b64url_decode(parts[0]))
    except ValueError:
        raise malformed from None

    if not set(header) <= _ALLOWED_HEADER_MEMBERS:
        raise malformed
    typ, alg, jwk = header.get("typ"), header.get("alg"), header.get("jwk")
    if not isinstance(typ, str) or typ != DPOP_TYP:
        raise malformed
    if not isinstance(alg, str) or alg != SIGNING_ALG:
        raise malformed
    if not isinstance(jwk, dict) or not set(jwk) <= _ALLOWED_JWK_MEMBERS:
        raise malformed
    if "kty" not in jwk or "crv" not in jwk:
        raise malformed
    try:
        model = PublicJWK.model_validate(jwk, strict=True)
        raw = _b64url_decode(model.x)
    except (ValidationError, ValueError):
        raise malformed from None
    # Exactly one spelling per key: a non-canonical ``x`` would decode to the same key
    # but could produce a different thumbprint elsewhere.
    if len(raw) != 32 or _b64url(raw) != model.x:
        raise malformed
    try:
        public_key = Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise malformed from None
    return model, public_key, parts[1]


def _verify_signature(proof: str, public_key: Ed25519PublicKey) -> None:
    """Check the EdDSA signature with the key embedded in the header.

    ``algorithms`` is pinned to EdDSA, so the library can never be talked into another
    algorithm by the token. An invalid signature is BAD_SIGNATURE; any other library
    complaint (e.g. a payload that is not JSON) is MALFORMED.
    """
    try:
        jwt.decode(proof, public_key, algorithms=[SIGNING_ALG], options=_SIGNATURE_ONLY_OPTIONS)
    except jwt.InvalidSignatureError:
        raise DPoPError(ReasonCode.DPOP_BAD_SIGNATURE) from None
    except jwt.PyJWTError:
        raise DPoPError(ReasonCode.DPOP_MALFORMED) from None


def _parse_claims(payload_segment: str) -> DPoPProofClaims:
    """Validate the (now authenticated) claims strictly: no type coercion, no extras.

    Without strict mode ``"iat": "1800000000"`` would be silently turned into an int;
    a verifier should only accept exactly what the contract says.
    """
    try:
        payload = _strict_json_object(_b64url_decode(payload_segment))
        return DPoPProofClaims.model_validate(payload, strict=True)
    except (ValidationError, ValueError):
        raise DPoPError(ReasonCode.DPOP_MALFORMED) from None


def _check_key(jwk: PublicJWK, expected_jkt: str | None) -> None:
    """The proof key must be the key the token is bound to (``cnf.jkt``).

    ``None`` means the caller has no binding to check (e.g. a first contact). An empty
    or non-string value is a caller bug and fails closed rather than skipping the check.
    """
    if expected_jkt is None:
        return
    if not isinstance(expected_jkt, str) or not _ct_equal(jwk_thumbprint(jwk), expected_jkt):
        raise DPoPError(ReasonCode.DPOP_KEY_MISMATCH)


def _check_request(claims: DPoPProofClaims, htm: str, htu: str) -> None:
    """The proof must be for *this* request, so it cannot be reused on another endpoint.

    Both are exact string compares (methods are case-sensitive; URLs are not normalized,
    because normalization rules are where parser-confusion bugs live).
    """
    if not isinstance(htm, str) or not htm or claims.htm != htm:
        raise DPoPError(ReasonCode.DPOP_HTM_MISMATCH)
    if (
        not isinstance(htu, str)
        or not htu
        or _has_query_or_fragment(claims.htu)
        or claims.htu != htu
    ):
        raise DPoPError(ReasonCode.DPOP_HTU_MISMATCH)


def _check_fresh(iat: int, now: int, max_age: int) -> None:
    """``iat`` must be within ``max_age`` seconds of now (inclusive), in both directions.

    Too old means a captured proof is being reused; too far in the future means someone
    pre-dated a proof so it would stay usable longer than allowed.
    """
    if not (now - max_age <= iat <= now + max_age):
        raise DPoPError(ReasonCode.DPOP_STALE)


def _check_ath(claims: DPoPProofClaims, access_token: str | None) -> None:
    """Bind the proof to the exact access token sent with it.

    Without this, a proof made for one token could be paired with another. A proof that
    claims a token binding when no token was presented is also refused.
    """
    if access_token is None:
        if claims.ath is not None:
            raise DPoPError(ReasonCode.DPOP_ATH_MISMATCH)
        return
    if claims.ath is None or not isinstance(access_token, str):
        raise DPoPError(ReasonCode.DPOP_ATH_MISMATCH)
    try:
        expected = access_token_hash(access_token)
    except ValueError:
        raise DPoPError(ReasonCode.DPOP_ATH_MISMATCH) from None
    if not _ct_equal(expected, claims.ath):
        raise DPoPError(ReasonCode.DPOP_ATH_MISMATCH)


# ------------------------------------------------------------------ verify_proof


def verify_proof(
    proof: Any,
    *,
    htm: str,
    htu: str,
    expected_jkt: str | None = None,
    access_token: str | None = None,
    replay_cache: ReplayCache,
    max_age: int,
    now: int | None = None,
) -> PublicJWK:
    """Verify a DPoP proof and return the public key it was signed with.

    Raises ``DPoPError`` with the first failing reason (order in the module docstring).
    The replay cache is touched last, only for an otherwise-valid proof.
    """
    if not isinstance(replay_cache, ReplayCache):
        raise TypeError("replay_cache must be a ReplayCache")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
        raise ValueError("max_age must be a positive integer number of seconds")
    current = _now(now)

    jwk, public_key, payload_segment = _parse_header(proof)
    _verify_signature(proof, public_key)
    claims = _parse_claims(payload_segment)
    _check_key(jwk, expected_jkt)
    _check_request(claims, htm, htu)
    _check_fresh(claims.iat, current, max_age)
    _check_ath(claims, access_token)
    if not replay_cache.check_and_store(claims.jti, current, claims.iat + max_age):
        raise DPoPError(ReasonCode.DPOP_REPLAY)
    return jwk
