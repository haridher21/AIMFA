"""Tests for aimfa/common/dpop.py (ROADMAP T1.2: DPoP proofs, RFC 9449 simplified).

Written from ROADMAP T1.2 and the CONTRACTS.md "DPoP proof rules" table, before the
implementation exists.

Interface assumptions (the spec leaves these open; this is the simplest reading):
* ``make_proof(private_key, htm, htu, access_token=None, now=None) -> str`` takes an
  ``Ed25519PrivateKey`` (from ``crypto.generate_keypair()``). ``now`` is Unix seconds
  (int); ``iat`` is set to exactly ``int(now)``. With ``now=None`` it uses the real clock.
  It adds ``ath`` only when ``access_token`` is given.
* ``ath`` = base64url-without-padding(SHA-256(access_token encoded as ASCII)).
* ``verify_proof(proof, *, htm, htu, expected_jkt=None, access_token=None, replay_cache,
  max_age, now=None) -> PublicJWK`` returns the proof's embedded public key as a
  ``PublicJWK`` (equal to ``crypto.public_jwk(key)``). On failure it raises
  ``DPoPError`` whose ``.reason_code`` is a ``ReasonCode``.
* ``DPoPError(reason_code)`` is an ``Exception`` subclass; ``.reason_code`` is the
  constructor argument.
* ``ReplayCache(max_age=<seconds>)``: entries live for TTL = 2 x max_age. The cache uses
  the ``now`` that ``verify_proof`` was given (injected clock), not the wall clock.
  Only the constructor is used here; all cache behavior is tested through
  ``verify_proof`` so the cache's method names stay an implementation detail.

Team decisions (stated here so the implementer and reviewer can check them):
1. ``typ`` must be exactly ``"dpop+jwt"``. Case variants (``"DPoP+JWT"``) and the long
   form ``"application/dpop+jwt"`` are rejected (fail closed; RFC 9449 would allow a
   case-insensitive compare, we choose the stricter exact match).
2. ``alg`` must be exactly ``"EdDSA"``.
3. The header ``jwk`` is validated as a ``PublicJWK`` (``extra="forbid"``): only
   ``kty=OKP``, ``crv=Ed25519``, a 43-char ``x`` and an optional ``kid``. Any other member
   (``d``, ``use``, ...) means ``DPOP_MALFORMED``. ``kty`` and ``crv`` must be PRESENT in
   the header: ``PublicJWK`` gives them defaults, so validating with the model alone is
   not enough.
4. Claims are validated strictly against ``DPoPProofClaims``: no type coercion, so an
   ``iat`` of ``"1800000000"`` (string) or ``1800000000.5`` (float) is ``DPOP_MALFORMED``.
5. ``htm`` is compared exactly and case-sensitively (HTTP methods are case-sensitive,
   RFC 9110), so ``"post"`` != ``"POST"``.
6. ``htu`` is compared as an exact string, with no URL normalization. Any query
   (even a bare ``?``), fragment, trailing slash, scheme/host/port/path difference,
   percent-encoding, dot-segment, or case difference is ``DPOP_HTU_MISMATCH``.
7. The ``iat`` window is inclusive: valid iff ``now - max_age <= iat <= now + max_age``.
8. ``ath`` present when NO access token is given is rejected with ``DPOP_ATH_MISMATCH``
   (the proof claims a token binding that does not match the request). An empty-string
   access token is still "given" (it is not ``None``), so ``ath`` is required.
9. ``expected_jkt=""`` is not "no check": it fails with ``DPOP_KEY_MISMATCH``.
10. Non-string input (``None``, int, dict) is ``DPOP_MALFORMED``. (A missing header is
    mapped to ``DPOP_MISSING`` by the caller, not by ``verify_proof``.)
11. Check order when several things are wrong:
    MALFORMED (header) -> BAD_SIGNATURE -> KEY_MISMATCH -> HTM -> HTU -> STALE -> ATH ->
    REPLAY. A ``jti`` is recorded in the replay cache ONLY when the proof passed every
    other check, so a failed or forged proof can never "burn" a victim's ``jti``.
12. A replayed proof is rejected for as long as it would otherwise be fresh, including
    the last inclusive second of its ``iat`` window.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Imported as modules so ruff's isort treats them as first-party before and after
# dpop.py exists.
from aimfa.common import crypto, dpop
from aimfa.common.models import (
    GATEWAY_AUDIENCE,
    TOKEN_ISSUER,
    PublicJWK,
    ReasonCode,
)

DPoPError = dpop.DPoPError
ReplayCache = dpop.ReplayCache
make_proof = dpop.make_proof
verify_proof = dpop.verify_proof

generate_keypair = crypto.generate_keypair
jwk_thumbprint = crypto.jwk_thumbprint
public_jwk = crypto.public_jwk
sign_jwt = crypto.sign_jwt

NOW = 1_800_000_000  # fixed injected clock (Unix seconds)
MAX_AGE = 60  # Settings.dpop_max_age_seconds default
HTU = "http://127.0.0.1:8100/tool"  # gateway endpoint
TOKEN_HTU = "http://127.0.0.1:8000/token"  # control plane STS endpoint
APPROVAL_HTU = "http://127.0.0.1:8000/approvals/apr-0123456789abcdef"
# Opaque to dpop.py: it only hashes the token, never parses it.
ACCESS_TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJleHBlbnNlLWJvdCJ9.ZmFrZS1zaWduYXR1cmU"
OTHER_ACCESS_TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJvdGhlci1ib3QifQ.ZmFrZS1zaWduYXR1cmU"

_DROP = object()  # sentinel: remove this header member / claim


def _id(value: Any) -> str:
    """Stable, short pytest ids (the sentinel's repr would contain a memory address)."""
    return "DROP" if value is _DROP else repr(value)[:40]


# ------------------------------------------------------------------ helpers


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_json(obj: Any) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _ath(token: str) -> str:
    return _b64url(hashlib.sha256(token.encode("ascii")).digest())


def _jti() -> str:
    return secrets.token_urlsafe(24)


def _jwk_dict(key: Ed25519PrivateKey) -> dict:
    return public_jwk(key).model_dump(exclude_none=True)


def _apply(base: dict, overrides: dict) -> dict:
    out = dict(base)
    for k, v in overrides.items():
        if v is _DROP:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def _header(key: Ed25519PrivateKey, **overrides: Any) -> dict:
    return _apply({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": _jwk_dict(key)}, overrides)


def _payload(**overrides: Any) -> dict:
    return _apply({"jti": _jti(), "htm": "POST", "htu": HTU, "iat": NOW}, overrides)


def _sign_segments(h_b64: str, p_b64: str, signer: Ed25519PrivateKey | None) -> str:
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = signer.sign(signing_input) if signer is not None else b""
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _forge(header: Any, payload: Any, signer: Ed25519PrivateKey | None) -> str:
    """Hand-build a compact JWS so we control every header member and claim."""
    return _sign_segments(_b64url_json(header), _b64url_json(payload), signer)


def _proof(
    key: Ed25519PrivateKey,
    *,
    header: dict | None = None,
    signer: Ed25519PrivateKey | None = None,
    **claims: Any,
) -> str:
    """A proof for ``key`` (signed by ``key`` unless ``signer`` is given)."""
    return _forge(_header(key, **(header or {})), _payload(**claims), signer or key)


def _split(proof: str) -> tuple[dict, dict, str]:
    h, p, s = proof.split(".")
    return json.loads(_b64url_decode(h)), json.loads(_b64url_decode(p)), s


def _verify(
    proof: Any,
    *,
    cache: Any = None,
    htm: str = "POST",
    htu: str = HTU,
    expected_jkt: str | None = None,
    access_token: str | None = None,
    max_age: int = MAX_AGE,
    now: int | None = NOW,
) -> PublicJWK:
    return verify_proof(
        proof,
        htm=htm,
        htu=htu,
        expected_jkt=expected_jkt,
        access_token=access_token,
        replay_cache=cache if cache is not None else ReplayCache(max_age=max_age),
        max_age=max_age,
        now=now,
    )


def _expect(reason: ReasonCode, proof: Any, **kwargs: Any) -> DPoPError:
    with pytest.raises(DPoPError) as exc_info:
        _verify(proof, **kwargs)
    assert exc_info.value.reason_code == reason, exc_info.value.reason_code
    return exc_info.value


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return generate_keypair()


@pytest.fixture
def other_key() -> Ed25519PrivateKey:
    return generate_keypair()


@pytest.fixture
def cache():
    return ReplayCache(max_age=MAX_AGE)


# ------------------------------------------------------------------ DPoPError


def test_dpop_error_carries_its_reason_code():
    err = DPoPError(ReasonCode.DPOP_REPLAY)
    assert isinstance(err, Exception)
    assert err.reason_code == ReasonCode.DPOP_REPLAY


# ------------------------------------------------------------------ make_proof


def test_make_proof_has_dpop_header_with_public_jwk(key):
    proof = make_proof(key, "POST", HTU, now=NOW)
    assert isinstance(proof, str)
    assert proof.count(".") == 2
    header, _payload_, _sig = _split(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "EdDSA"
    assert header["jwk"] == _jwk_dict(key)
    assert "d" not in header["jwk"]


def test_make_proof_claims_bind_method_url_and_time(key):
    _h, claims, _s = _split(make_proof(key, "POST", HTU, now=NOW))
    assert claims["htm"] == "POST"
    assert claims["htu"] == HTU
    assert claims["iat"] == NOW
    assert type(claims["iat"]) is int
    assert isinstance(claims["jti"], str)
    assert len(claims["jti"]) >= 16
    assert "ath" not in claims  # no access token given


def test_make_proof_jti_is_unique_per_proof(key):
    jtis = {_split(make_proof(key, "POST", HTU, now=NOW))[1]["jti"] for _ in range(50)}
    assert len(jtis) == 50


def test_make_proof_with_access_token_sets_ath_to_base64url_sha256(key):
    _h, claims, _s = _split(make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW))
    assert claims["ath"] == _ath(ACCESS_TOKEN)
    assert "=" not in claims["ath"]
    assert len(claims["ath"]) == 43


def test_make_proof_signature_is_real_eddsa_over_embedded_key(key):
    proof = make_proof(key, "POST", HTU, now=NOW)
    decoded = jwt.decode(
        proof,
        key.public_key(),
        algorithms=["EdDSA"],
        options={"verify_aud": False, "verify_iat": False},
    )
    assert decoded["htu"] == HTU


def test_make_proof_never_contains_private_key_material(key):
    raw_d = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    proof = make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW)
    header, claims, _s = _split(proof)
    assert _b64url(raw_d) not in json.dumps(header)
    assert _b64url(raw_d) not in json.dumps(claims)
    assert ACCESS_TOKEN not in proof  # only the hash of the token is embedded


# ------------------------------------------------------------------ valid proofs


def test_valid_proof_passes_and_returns_the_proof_public_jwk(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    jwk = _verify(proof, cache=cache)
    assert isinstance(jwk, PublicJWK)
    assert jwk.x == public_jwk(key).x
    assert jwk_thumbprint(jwk) == jwk_thumbprint(public_jwk(key))


def test_valid_proof_with_matching_expected_jkt_passes(key):
    proof = make_proof(key, "POST", HTU, now=NOW)
    jwk = _verify(proof, expected_jkt=jwk_thumbprint(public_jwk(key)))
    assert jwk.x == public_jwk(key).x


def test_valid_proof_bound_to_the_presented_access_token_passes(key):
    proof = make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW)
    jwk = _verify(proof, access_token=ACCESS_TOKEN, expected_jkt=jwk_thumbprint(public_jwk(key)))
    assert jwk.x == public_jwk(key).x


@pytest.mark.parametrize(("htm", "htu"), [("POST", TOKEN_HTU), ("GET", APPROVAL_HTU)])
def test_valid_proof_for_other_endpoints_passes(key, htm, htu):
    proof = make_proof(key, htm, htu, now=NOW)
    assert _verify(proof, htm=htm, htu=htu).x == public_jwk(key).x


def test_proof_made_with_the_real_clock_verifies_with_the_real_clock(key):
    proof = make_proof(key, "POST", HTU)
    assert _verify(proof, now=None).x == public_jwk(key).x


def test_hand_built_proof_passes(key):
    # Control test: proves the forging helper builds valid proofs, so the negative tests
    # below fail for the reason they claim, not because the helper is broken.
    assert _verify(_proof(key)).x == public_jwk(key).x
    assert _verify(_proof(key, ath=_ath(ACCESS_TOKEN)), access_token=ACCESS_TOKEN)


def test_jti_of_exactly_16_chars_is_accepted(key):
    assert _verify(_proof(key, jti="a" * 16)).x == public_jwk(key).x


# ------------------------------------------------------------------ DPOP_MALFORMED


@pytest.mark.parametrize(
    "proof",
    [
        "",
        "   ",
        "not-a-jwt",
        "a.b",
        "a.b.c",
        "a.b.c.d",
        "a.b.c.d.e",  # JWE-shaped
        "..",
        "!!!.???.***",
        "é.é.é",
        None,
        12345,
        {"typ": "dpop+jwt"},
    ],
    ids=_id,
)
def test_non_jwt_input_is_malformed(proof):
    _expect(ReasonCode.DPOP_MALFORMED, proof)


@pytest.mark.parametrize(
    ("header_raw", "payload_raw"),
    [
        (b"not json", None),
        (b'["dpop+jwt"]', None),
        (b'"dpop+jwt"', None),
        (None, b"not json"),
        (None, b"[1,2,3]"),
        (None, b"null"),
        (None, b'"a string"'),
    ],
    ids=[
        "header_not_json",
        "header_array",
        "header_string",
        "payload_not_json",
        "payload_array",
        "payload_null",
        "payload_string",
    ],
)
def test_header_or_payload_that_is_not_a_json_object_is_malformed(key, header_raw, payload_raw):
    h = _b64url(header_raw) if header_raw is not None else _b64url_json(_header(key))
    p = _b64url(payload_raw) if payload_raw is not None else _b64url_json(_payload())
    _expect(ReasonCode.DPOP_MALFORMED, _sign_segments(h, p, key))


@pytest.mark.parametrize(
    "typ",
    [
        "JWT",
        "jwt",
        "at+jwt",
        "DPoP+JWT",
        "DPOP+JWT",
        "application/dpop+jwt",
        "dpop+jwt ",
        " dpop+jwt",
        "dpop",
        "",
        None,
        ["dpop+jwt"],
        _DROP,
    ],
    ids=_id,
)
def test_wrong_or_missing_typ_is_malformed(key, typ):
    # Validly signed by the embedded key: only typ is wrong.
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"typ": typ}))


@pytest.mark.parametrize(
    "alg",
    [
        "none",
        "None",
        "NONE",
        "HS256",
        "ES256",
        "RS256",
        "eddsa",
        "EDDSA",
        "Ed25519",
        "",
        None,
        _DROP,
    ],
    ids=_id,
)
def test_wrong_or_missing_alg_is_malformed(key, alg):
    # Signed with the right Ed25519 key, but the header lies about (or omits) alg.
    # The verifier must pin EdDSA, never trust the header's choice.
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"alg": alg}))


@pytest.mark.parametrize("alg", ["none", "None", "nOnE"])
def test_unsigned_alg_none_proof_is_malformed(key, alg):
    proof = _forge(_header(key, alg=alg), _payload(), signer=None)
    assert proof.endswith(".")
    _expect(ReasonCode.DPOP_MALFORMED, proof)


def test_hs256_proof_forged_with_public_key_as_secret_is_malformed(key):
    # alg confusion: the embedded jwk is public, so an attacker can HMAC with its bytes.
    header = _header(key, alg="HS256")
    h, p = _b64url_json(header), _b64url_json(_payload())
    secret = public_jwk(key).x.encode("ascii")
    sig = hmac.new(secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    _expect(ReasonCode.DPOP_MALFORMED, f"{h}.{p}.{_b64url(sig)}")


def test_es256_proof_with_ec_jwk_is_malformed():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key()))
    proof = jwt.encode(
        _payload(), ec_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": ec_jwk}
    )
    _expect(ReasonCode.DPOP_MALFORMED, proof)


_JWK_VARIANTS: list[tuple[str, Callable[[dict], Any]]] = [
    ("missing", lambda j: _DROP),
    ("null", lambda j: None),
    ("json_string", lambda j: json.dumps(j)),
    ("list", lambda j: [j]),
    ("empty_object", lambda j: {}),
    ("kty_EC", lambda j: {**j, "kty": "EC"}),
    ("kty_RSA", lambda j: {**j, "kty": "RSA"}),
    ("kty_oct", lambda j: {"kty": "oct", "k": j["x"]}),
    ("kty_lowercase", lambda j: {**j, "kty": "okp"}),
    ("crv_X25519", lambda j: {**j, "crv": "X25519"}),
    ("crv_Ed448", lambda j: {**j, "crv": "Ed448"}),
    # PublicJWK has defaults for kty/crv, so model validation alone would accept these.
    # RFC 8037 requires both members to be present in the header jwk.
    ("missing_kty", lambda j: {k: v for k, v in j.items() if k != "kty"}),
    ("missing_crv", lambda j: {k: v for k, v in j.items() if k != "crv"}),
    ("missing_x", lambda j: {k: v for k, v in j.items() if k != "x"}),
    ("x_42_chars", lambda j: {**j, "x": j["x"][:42]}),
    ("x_44_chars", lambda j: {**j, "x": j["x"] + "A"}),
    ("x_padded", lambda j: {**j, "x": j["x"][:42] + "="}),
    ("x_int", lambda j: {**j, "x": 12345}),
    ("extra_member_use", lambda j: {**j, "use": "sig"}),
    ("extra_member_x5u", lambda j: {**j, "x5u": "http://evil.example/key"}),
]


@pytest.mark.parametrize("mutate", [m for _, m in _JWK_VARIANTS], ids=[n for n, _ in _JWK_VARIANTS])
def test_missing_or_invalid_jwk_is_malformed(key, mutate):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"jwk": mutate(_jwk_dict(key))}))


def test_private_jwk_with_d_is_malformed_and_d_is_not_echoed(key):
    # A client that leaks its private key in the header must be refused, not accepted.
    d = _b64url(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    proof = _proof(key, header={"jwk": {**_jwk_dict(key), "d": d}})
    err = _expect(ReasonCode.DPOP_MALFORMED, proof)
    assert d not in str(err)
    assert d not in repr(err)


def test_access_token_presented_as_proof_is_malformed(key):
    # Token-type confusion: a normal JWT (no typ=dpop+jwt, no jwk) is not a DPoP proof.
    token = sign_jwt(
        {
            "iss": TOKEN_ISSUER,
            "aud": GATEWAY_AUDIENCE,
            "sub": "expense-bot",
            "jti": _jti(),
            "htm": "POST",
            "htu": HTU,
            "iat": NOW,
            "exp": NOW + 300,
            "token_use": "access",
        },
        key,
    )
    _expect(ReasonCode.DPOP_MALFORMED, token)


@pytest.mark.parametrize("claim", ["jti", "htm", "htu", "iat"])
def test_missing_required_claim_is_malformed(key, claim):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, **{claim: _DROP}))


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("jti", "a" * 15),  # DPoPProofClaims: min_length=16
        ("jti", ""),
        ("jti", 1234567890123456789),
        ("jti", None),
        ("jti", ["a" * 16]),
        ("htm", 1),
        ("htm", None),
        ("htm", ["POST"]),
        ("htu", None),
        ("htu", 8100),
        ("htu", [HTU]),
        ("iat", str(NOW)),  # numeric string: no coercion
        ("iat", NOW + 0.5),  # fractional float
        ("iat", None),
        ("iat", [NOW]),
        ("ath", 12345),
        ("ath", [_ath(ACCESS_TOKEN)]),
    ],
    ids=_id,
)
def test_claim_with_wrong_type_or_shape_is_malformed(key, claim, value):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, **{claim: value}))


# ------------------------------------------------------------------ DPOP_BAD_SIGNATURE


def test_proof_signed_by_a_different_key_than_its_jwk_is_bad_signature(key, other_key):
    # Attacker puts the victim's public key in the header but can only sign with their own.
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, _proof(key, signer=other_key))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("htu", HTU),  # retarget a /token proof at the gateway
        ("htm", "POST"),  # retarget a GET proof as POST
        ("iat", NOW),  # refresh an old proof
        ("jti", "f" * 32),  # mint a "new" proof to dodge the replay cache
    ],
)
def test_tampered_payload_is_bad_signature(key, field, value):
    original = make_proof(key, "GET", TOKEN_HTU, now=NOW - 30)
    h, p, s = original.split(".")
    claims = json.loads(_b64url_decode(p))
    claims[field] = value
    forged = f"{h}.{_b64url_json(claims)}.{s}"
    assert forged != original
    _expect(
        ReasonCode.DPOP_BAD_SIGNATURE,
        forged,
        htm=claims["htm"],
        htu=claims["htu"],
    )


def test_swapped_jwk_header_is_bad_signature(key, other_key):
    # Attacker steals a victim's proof and swaps in their own public key.
    original = make_proof(key, "POST", HTU, now=NOW)
    _h, p, s = original.split(".")
    forged = f"{_b64url_json(_header(other_key))}.{p}.{s}"
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, forged)


def test_flipped_signature_byte_is_bad_signature(key):
    h, p, s = make_proof(key, "POST", HTU, now=NOW).split(".")
    sig = bytearray(_b64url_decode(s))
    sig[0] ^= 0x01
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{h}.{p}.{_b64url(bytes(sig))}")


def test_empty_signature_is_bad_signature(key):
    h, p, _s = make_proof(key, "POST", HTU, now=NOW).split(".")
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{h}.{p}.")


def test_signature_spliced_from_another_proof_is_bad_signature(key):
    h1, p1, _s1 = make_proof(key, "POST", HTU, now=NOW).split(".")
    _h2, _p2, s2 = make_proof(key, "POST", HTU, now=NOW).split(".")
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{h1}.{p1}.{s2}")


# ------------------------------------------------------------------ DPOP_KEY_MISMATCH


def test_valid_proof_from_another_key_is_key_mismatch(key, other_key):
    # Stolen access token + attacker's own key: the proof is well-formed and correctly
    # signed, but the key is not the one the token is bound to.
    proof = make_proof(other_key, "POST", HTU, now=NOW)
    _expect(
        ReasonCode.DPOP_KEY_MISMATCH,
        proof,
        expected_jkt=jwk_thumbprint(public_jwk(key)),
    )


def test_empty_expected_jkt_is_key_mismatch_not_skipped(key):
    # Fail closed: "" is a caller bug (e.g. token without cnf.jkt), not "no check".
    _expect(ReasonCode.DPOP_KEY_MISMATCH, make_proof(key, "POST", HTU, now=NOW), expected_jkt="")


@pytest.mark.parametrize(
    "variant",
    [
        lambda t: t + "=",
        lambda t: t + " ",
        lambda t: " " + t,
        lambda t: t.swapcase(),
        lambda t: t[:-1],
    ],
    ids=["padded", "trailing_space", "leading_space", "swapcase", "truncated"],
)
def test_near_miss_expected_jkt_is_key_mismatch(key, variant):
    jkt = jwk_thumbprint(public_jwk(key))
    _expect(
        ReasonCode.DPOP_KEY_MISMATCH,
        make_proof(key, "POST", HTU, now=NOW),
        expected_jkt=variant(jkt),
    )


# ------------------------------------------------------------------ DPOP_HTM_MISMATCH


@pytest.mark.parametrize(
    ("proof_htm", "expected_htm"),
    [
        ("GET", "POST"),
        ("POST", "GET"),
        ("PUT", "POST"),
        ("post", "POST"),  # methods are case-sensitive
        ("Post", "POST"),
        ("POST ", "POST"),
        (" POST", "POST"),
        ("", "POST"),
    ],
)
def test_wrong_method_is_htm_mismatch(key, proof_htm, expected_htm):
    _expect(ReasonCode.DPOP_HTM_MISMATCH, _proof(key, htm=proof_htm), htm=expected_htm)


# ------------------------------------------------------------------ DPOP_HTU_MISMATCH


@pytest.mark.parametrize(
    "proof_htu",
    [
        "https://127.0.0.1:8100/tool",  # scheme
        "HTTP://127.0.0.1:8100/tool",  # scheme case (no normalization)
        "http://localhost:8100/tool",  # host alias
        "http://127.0.0.2:8100/tool",
        "http://127.0.0.1:8000/tool",  # port (control plane)
        "http://127.0.0.1/tool",  # default port
        "http://127.0.0.1:8100/tool/",  # trailing slash
        "http://127.0.0.1:8100/Tool",  # path case
        "http://127.0.0.1:8100/tools",
        "http://127.0.0.1:8100/to",
        "http://127.0.0.1:8100",
        "http://127.0.0.1:8100/",
        "http://127.0.0.1:8100//tool",  # double slash
        "http://127.0.0.1:8100/x/../tool",  # dot segments
        "http://127.0.0.1:8100/./tool",
        "http://127.0.0.1:8100/%74ool",  # percent-encoded 't'
        "http://127.0.0.1:8100/%2e/tool",
        "http://127.0.0.1:8100\\tool",  # backslash
        "http://evil@127.0.0.1:8100/tool",  # userinfo
        "http://127.0.0.1:8100/tооl",  # Cyrillic homoglyph 'о'
        "http://127.0.0.1:8100/tool;x",
        "http://127.0.0.1:8100/tool\x00",
        " http://127.0.0.1:8100/tool",
        "http://127.0.0.1:8100/tool ",
        TOKEN_HTU,  # a valid proof for a different endpoint
        "",
    ],
    ids=_id,
)
def test_wrong_url_is_htu_mismatch(key, proof_htu):
    _expect(ReasonCode.DPOP_HTU_MISMATCH, _proof(key, htu=proof_htu))


@pytest.mark.parametrize(
    "suffix",
    ["?", "?a=1", "?htu=http://127.0.0.1:8100/tool", "#", "#frag", "?a=1#frag", "/?x"],
    ids=_id,
)
def test_url_with_query_or_fragment_is_htu_mismatch(key, suffix):
    proof = _proof(key, htu=HTU + suffix)
    _expect(ReasonCode.DPOP_HTU_MISMATCH, proof)


# ------------------------------------------------------------------ DPOP_STALE


@pytest.mark.parametrize(
    "iat",
    [NOW - MAX_AGE - 1, NOW - 3600, 0, -1, -(2**63)],
    ids=["one_second_too_old", "an_hour_old", "epoch", "negative", "huge_negative"],
)
def test_iat_too_old_is_stale(key, iat):
    _expect(ReasonCode.DPOP_STALE, _proof(key, iat=iat))


@pytest.mark.parametrize(
    "iat",
    [NOW + MAX_AGE + 1, NOW + 86400, 10**12, 2**63, 10**30],
    ids=["one_second_too_new", "a_day_ahead", "1e12", "2^63", "1e30"],
)
def test_iat_too_far_in_the_future_is_stale(key, iat):
    # Pre-dated proofs would let a stolen proof live longer than max_age.
    _expect(ReasonCode.DPOP_STALE, _proof(key, iat=iat))


@pytest.mark.parametrize("offset", [-MAX_AGE, MAX_AGE, 0])
def test_iat_exactly_at_max_age_boundary_passes(key, offset):
    assert _verify(_proof(key, iat=NOW + offset)).x == public_jwk(key).x


def test_max_age_parameter_is_honored(key):
    _expect(ReasonCode.DPOP_STALE, _proof(key, iat=NOW - 6), max_age=5)
    assert _verify(_proof(key, iat=NOW - 5), max_age=5).x == public_jwk(key).x


def test_old_proof_from_make_proof_is_stale(key):
    _expect(ReasonCode.DPOP_STALE, make_proof(key, "POST", HTU, now=NOW - MAX_AGE - 1))


# ------------------------------------------------------------------ DPOP_ATH_MISMATCH


def test_missing_ath_when_access_token_given_is_ath_mismatch(key):
    proof = make_proof(key, "POST", HTU, now=NOW)  # no access_token -> no ath
    _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=ACCESS_TOKEN)


def test_ath_for_a_different_token_is_ath_mismatch(key):
    proof = make_proof(key, "POST", HTU, access_token=OTHER_ACCESS_TOKEN, now=NOW)
    _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=ACCESS_TOKEN)


@pytest.mark.parametrize(
    "ath",
    [
        _ath(ACCESS_TOKEN) + "=",  # padded
        hashlib.sha256(ACCESS_TOKEN.encode("ascii")).hexdigest(),  # hex, not base64url
        _ath(ACCESS_TOKEN).swapcase(),
        _ath(ACCESS_TOKEN + "\n"),
        _ath(ACCESS_TOKEN)[:-1],
        ACCESS_TOKEN,  # the raw token instead of its hash
        "",
    ],
    ids=["padded", "hex", "swapcase", "token_with_newline", "truncated", "raw_token", "empty"],
)
def test_near_miss_ath_is_ath_mismatch(key, ath):
    _expect(ReasonCode.DPOP_ATH_MISMATCH, _proof(key, ath=ath), access_token=ACCESS_TOKEN)


def test_ath_present_without_an_access_token_is_ath_mismatch(key):
    # Team decision 8: a proof bound to a token is only valid alongside that token.
    proof = make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW)
    _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=None)


def test_empty_access_token_still_requires_ath(key):
    # "" is not None: fail closed instead of skipping the binding check.
    _expect(ReasonCode.DPOP_ATH_MISMATCH, make_proof(key, "POST", HTU, now=NOW), access_token="")


def test_ath_error_does_not_echo_the_access_token(key):
    proof = make_proof(key, "POST", HTU, access_token=OTHER_ACCESS_TOKEN, now=NOW)
    err = _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=ACCESS_TOKEN)
    for secret in (ACCESS_TOKEN, OTHER_ACCESS_TOKEN):
        assert secret not in str(err)
        assert secret not in repr(err)


# ------------------------------------------------------------------ DPOP_REPLAY


def test_same_proof_twice_is_replay(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    _verify(proof, cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache)


def test_same_proof_replayed_a_second_later_is_replay(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    _verify(proof, cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache, now=NOW + 1)


def test_same_jti_for_a_different_url_is_replay(key, cache):
    jti = _jti()
    _verify(_proof(key, jti=jti, htu=HTU), cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, _proof(key, jti=jti, htu=TOKEN_HTU), cache=cache, htu=TOKEN_HTU)


def test_same_jti_with_a_different_iat_is_replay(key, cache):
    jti = _jti()
    _verify(_proof(key, jti=jti, iat=NOW), cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, _proof(key, jti=jti, iat=NOW + 5), cache=cache, now=NOW + 5)


def test_replay_is_rejected_at_the_last_second_the_proof_is_fresh(key, cache):
    # A proof pre-dated by max_age, first seen now, stays fresh until now + 2*max_age
    # (inclusive window). The cache must still remember it then, which is why
    # TTL = 2 x max_age.
    proof = _proof(key, iat=NOW + MAX_AGE)
    _verify(proof, cache=cache, now=NOW)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache, now=NOW + 2 * MAX_AGE)


def test_replay_cache_forgets_jti_after_ttl(key, cache):
    # After TTL = 2 x max_age the entry may be dropped (any proof carrying that jti and
    # still fresh would need a new iat, which needs a new signature from the real key).
    jti = _jti()
    _verify(_proof(key, jti=jti, iat=NOW), cache=cache, now=NOW)
    later = NOW + 2 * MAX_AGE + 1
    assert _verify(_proof(key, jti=jti, iat=later), cache=cache, now=later).x == public_jwk(key).x


def _failing_variant(kind: str, victim: Ed25519PrivateKey, attacker: Ed25519PrivateKey, jti: str):
    """A proof carrying ``jti`` that fails with ``kind``, plus verify kwargs."""
    if kind == "bad_signature":
        return _proof(victim, jti=jti, signer=attacker), {}
    if kind == "key_mismatch":
        return _proof(attacker, jti=jti), {"expected_jkt": jwk_thumbprint(public_jwk(victim))}
    if kind == "htm":
        return _proof(victim, jti=jti, htm="GET"), {}
    if kind == "htu":
        return _proof(victim, jti=jti, htu=TOKEN_HTU), {}
    if kind == "stale":
        return _proof(victim, jti=jti, iat=NOW - 10 * MAX_AGE), {}
    if kind == "ath":
        return _proof(victim, jti=jti, ath=_ath(OTHER_ACCESS_TOKEN)), {"access_token": ACCESS_TOKEN}
    if kind == "malformed":
        return _proof(victim, jti=jti, header={"typ": "JWT"}), {}
    raise AssertionError(kind)


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("malformed", ReasonCode.DPOP_MALFORMED),
        ("bad_signature", ReasonCode.DPOP_BAD_SIGNATURE),
        ("key_mismatch", ReasonCode.DPOP_KEY_MISMATCH),
        ("htm", ReasonCode.DPOP_HTM_MISMATCH),
        ("htu", ReasonCode.DPOP_HTU_MISMATCH),
        ("stale", ReasonCode.DPOP_STALE),
        ("ath", ReasonCode.DPOP_ATH_MISMATCH),
    ],
)
def test_rejected_proof_does_not_burn_the_jti(key, other_key, cache, kind, reason):
    # If failed proofs were recorded, an attacker could pre-submit junk carrying a
    # victim's jti and make the victim's real request fail as a "replay".
    jti = _jti()
    bad, kwargs = _failing_variant(kind, victim=key, attacker=other_key, jti=jti)
    _expect(reason, bad, cache=cache, **kwargs)
    good = _proof(key, jti=jti, ath=_ath(ACCESS_TOKEN))
    jwk = _verify(
        good,
        cache=cache,
        access_token=ACCESS_TOKEN,
        expected_jkt=jwk_thumbprint(public_jwk(key)),
    )
    assert jwk.x == public_jwk(key).x


def test_concurrent_identical_proofs_exactly_one_succeeds(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    n = 16
    barrier = threading.Barrier(n)
    lock = threading.Lock()
    successes: list[PublicJWK] = []
    reasons: list[Any] = []

    def worker() -> None:
        barrier.wait()
        try:
            jwk = _verify(proof, cache=cache)
        except DPoPError as exc:
            with lock:
                reasons.append(exc.reason_code)
        except Exception as exc:  # any other crash is a test failure
            with lock:
                reasons.append(exc)
        else:
            with lock:
                successes.append(jwk)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(successes) == 1
    assert reasons == [ReasonCode.DPOP_REPLAY] * (n - 1)


def test_concurrent_distinct_proofs_all_pass_and_none_are_lost(key, cache):
    # No lost updates: every jti accepted concurrently must be remembered afterwards.
    n_threads, per_thread = 8, 25
    proofs = [
        [make_proof(key, "POST", HTU, now=NOW) for _ in range(per_thread)] for _ in range(n_threads)
    ]
    barrier = threading.Barrier(n_threads)
    errors: list[Any] = []
    lock = threading.Lock()

    def worker(batch: list[str]) -> None:
        barrier.wait()
        for p in batch:
            try:
                _verify(p, cache=cache)
            except Exception as exc:
                with lock:
                    errors.append(exc)

    threads = [threading.Thread(target=worker, args=(b,)) for b in proofs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert errors == []
    for batch in proofs:
        for p in batch:
            _expect(ReasonCode.DPOP_REPLAY, p, cache=cache)


# ------------------------------------------------------------------ check ordering


def _seed(cache: Any, key: Ed25519PrivateKey, jti: str) -> None:
    _verify(_proof(key, jti=jti), cache=cache)


_ORDER_CASES: list[tuple[str, Callable[..., tuple[str, dict]], ReasonCode]] = [
    (
        "malformed_typ_beats_bad_signature",
        lambda k, o, c: (_proof(k, header={"typ": "JWT"}, signer=o), {}),
        ReasonCode.DPOP_MALFORMED,
    ),
    (
        "malformed_jwk_d_beats_bad_signature",
        lambda k, o, c: (_proof(k, header={"jwk": {**_jwk_dict(k), "d": "A" * 43}}, signer=o), {}),
        ReasonCode.DPOP_MALFORMED,
    ),
    (
        "bad_signature_beats_key_mismatch",
        lambda k, o, c: (_proof(o, signer=k), {"expected_jkt": jwk_thumbprint(public_jwk(k))}),
        ReasonCode.DPOP_BAD_SIGNATURE,
    ),
    (
        "bad_signature_beats_htm_htu_stale_ath",
        lambda k, o, c: (
            _proof(k, signer=o, htm="GET", htu=TOKEN_HTU, iat=0, ath="x" * 43),
            {"access_token": ACCESS_TOKEN},
        ),
        ReasonCode.DPOP_BAD_SIGNATURE,
    ),
    (
        "key_mismatch_beats_htm",
        lambda k, o, c: (_proof(o, htm="GET"), {"expected_jkt": jwk_thumbprint(public_jwk(k))}),
        ReasonCode.DPOP_KEY_MISMATCH,
    ),
    (
        "htm_beats_htu",
        lambda k, o, c: (_proof(k, htm="GET", htu=TOKEN_HTU), {}),
        ReasonCode.DPOP_HTM_MISMATCH,
    ),
    (
        "htu_beats_stale",
        lambda k, o, c: (_proof(k, htu=TOKEN_HTU, iat=0), {}),
        ReasonCode.DPOP_HTU_MISMATCH,
    ),
    (
        "stale_beats_ath",
        lambda k, o, c: (_proof(k, iat=0, ath="x" * 43), {"access_token": ACCESS_TOKEN}),
        ReasonCode.DPOP_STALE,
    ),
    (
        "stale_beats_replay",
        lambda k, o, c: (
            _seed(c, k, "s" * 20) or _proof(k, jti="s" * 20, iat=NOW - 10 * MAX_AGE),
            {},
        ),
        ReasonCode.DPOP_STALE,
    ),
    (
        "ath_beats_replay",
        lambda k, o, c: (
            _seed(c, k, "r" * 20) or _proof(k, jti="r" * 20, ath=_ath(OTHER_ACCESS_TOKEN)),
            {"access_token": ACCESS_TOKEN},
        ),
        ReasonCode.DPOP_ATH_MISMATCH,
    ),
]


@pytest.mark.parametrize(
    ("build", "reason"),
    [(b, r) for _, b, r in _ORDER_CASES],
    ids=[n for n, _, _ in _ORDER_CASES],
)
def test_check_order_when_several_things_are_wrong(key, other_key, cache, build, reason):
    # Order: MALFORMED -> BAD_SIGNATURE -> KEY_MISMATCH -> HTM -> HTU -> STALE -> ATH -> REPLAY.
    # Nothing about an unauthenticated proof (wrong htm, stale, ...) is reported before its
    # signature is checked, and the replay cache is only consulted for otherwise-valid proofs.
    proof, kwargs = build(key, other_key, cache)
    _expect(reason, proof, cache=cache, **kwargs)
