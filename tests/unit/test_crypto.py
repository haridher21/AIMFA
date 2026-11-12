"""Tests for aimfa/common/crypto.py (ROADMAP T1.1: crypto helpers).

Written from the ROADMAP spec, before the implementation exists.

Interface assumptions (the spec leaves these open; this is the simplest reading):
* ``generate_keypair()`` returns a ``cryptography`` ``Ed25519PrivateKey``. The public key
  is ``key.public_key()``.
* ``save_private_key(key, path)`` / ``load_private_key(path) -> Ed25519PrivateKey``. The
  file is unencrypted PKCS#8 PEM. ``load_private_key`` refuses anything that is not an
  Ed25519 private key (``ValueError`` or ``TypeError``).
* ``public_jwk(key)`` accepts either the private key or its public key.
* ``jwk_thumbprint(jwk)`` takes a ``PublicJWK``.
* ``sign_jwt(claims, key, headers=None)`` takes an ``Ed25519PrivateKey``.
* ``verify_jwt(token, public_key, audience, issuer)`` takes an ``Ed25519PublicKey`` and
  returns the claims dict. On failure it raises PyJWT's ``jwt.InvalidTokenError`` (or a
  subclass). Expiry raises ``jwt.ExpiredSignatureError``, so callers can map it to
  ``TOKEN_EXPIRED`` and everything else to ``TOKEN_INVALID`` (or ``STS_IDENTITY_INVALID``).
  crypto.py itself is context-free, so it does not pick the ``ReasonCode``.
* ``verify_jwt`` requires ``exp``, ``aud`` and ``iss`` (AGENTS.md rule 2) and uses no
  leeway, so a token whose ``exp`` equals the current second is already expired.
* ``measure(code_paths, system_prompt, tool_manifest, model_id, *, root)``: ``code_paths``
  is a list of ``str``/``Path``; ``tool_manifest`` is a JSON-serializable object (dict).
  (See revised decision 3.)
* ``sha256_hex(data)`` takes ``bytes``.

Team decisions (coordinator, after the first draft):
1. ``verify_jwt(token, public_key, audience, issuer, *, token_use: str | None = None)``.
   When ``token_use`` is given, the token MUST carry a ``token_use`` claim exactly equal
   to it (no case folding, no trimming), else ``jwt.InvalidTokenError``. This blocks
   token-type confusion (AGENTS.md rule 2).
2. No ``now=`` on ``verify_jwt``; zero leeway (the exp-boundary test uses the real clock).
3. REVISED (security review): ``measure(code_paths, system_prompt, tool_manifest,
   model_id, *, root)`` with ``root`` keyword-only and required. Each file is bound to its
   POSIX path relative to ``root`` (sorted ``[relpath, sha256]`` pairs are hashed), so:
   order-independent; swapping two files' contents or renaming a file changes the
   measurement; the same tree under two different absolute roots gives the SAME
   measurement; a code path outside ``root`` -> ``ValueError``; empty ``code_paths`` ->
   ``ValueError``.
4. ``jwk_thumbprint`` takes a ``PublicJWK`` only. ``x`` must strictly base64url-decode to
   exactly 32 bytes AND re-encode to the identical string, else ``ValueError`` (one key
   must have exactly one thumbprint).
5. ``canonical_json(obj)`` is exactly ``json.dumps(obj, sort_keys=True,
   separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")``
   (CONTRACTS.md formula plus ``allow_nan=False``; valid output is byte-identical) with
   no ``default=`` fallback: non-JSON types such as ``datetime`` raise ``TypeError`` (so
   callers must ``model_dump(mode="json")`` first) and NaN/Infinity raise ``ValueError``.

Security-review follow-up decisions:
6. ``verify_jwt`` rejects (``jwt.InvalidTokenError``) validly signed tokens carrying a
   ``crit`` header, a ``b64`` header (RFC 7797 unencoded payload), or a list-valued
   ``aud`` (even ``["aimfa-sts"]``).
7. ``verify_jwt`` with an empty-string ``audience`` and/or ``issuer`` raises
   ``ValueError`` (a caller programming error, not a bad token).
8. ``sign_jwt`` header allowlist: ``headers`` may only contain ``typ``, ``jwk``, ``kid``;
   any other key (``alg``, ``ALG``, ``crit``, ``b64``, ``x5u``, ``jku``...) ->
   ``ValueError``. A ``jwk`` header must validate as ``PublicJWK`` (``extra="forbid"``)
   and is emitted as the public JWK only (``kid`` omitted when unset); anything else
   (private ``d``, ``kty=oct``, a string) -> ``ValueError``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Imported as a module (not ``from aimfa.common.crypto import ...``) so ruff's isort
# classifies it as first-party both before and after crypto.py exists.
from aimfa.common import crypto
from aimfa.common.models import (
    GATEWAY_AUDIENCE,
    SHA256_HEX_PATTERN,
    STS_AUDIENCE,
    TOKEN_ISSUER,
    PublicJWK,
)

canonical_json = crypto.canonical_json
generate_keypair = crypto.generate_keypair
jwk_thumbprint = crypto.jwk_thumbprint
load_private_key = crypto.load_private_key
measure = crypto.measure
public_jwk = crypto.public_jwk
save_private_key = crypto.save_private_key
sha256_hex = crypto.sha256_hex
sign_jwt = crypto.sign_jwt
verify_jwt = crypto.verify_jwt

# RFC 8037 Appendix A.1 / A.3 Ed25519 example key and its RFC 7638 thumbprint.
RFC8037_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

B64URL_NOPAD = re.compile(r"^[A-Za-z0-9_-]+$")


# ------------------------------------------------------------------ helpers


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _claims(aud: str = STS_AUDIENCE, exp_offset: int = 300, **extra) -> dict:
    now = int(time.time())
    claims = {
        "iss": TOKEN_ISSUER,
        "sub": "expense-bot",
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
        "jti": "jti-0123456789abcdef",
        "token_use": "identity",
    }
    claims.update(extra)
    return claims


def _raw_public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verify(token, key: Ed25519PrivateKey, audience=STS_AUDIENCE, issuer=TOKEN_ISSUER):
    return verify_jwt(token, key.public_key(), audience, issuer)


def _sign_raw(header: dict, claims: dict, key: Ed25519PrivateKey) -> str:
    """Validly EdDSA-sign any header/claims, bypassing sign_jwt's own checks.

    Lets a negative test isolate exactly one verifier check: the signature is good, so
    only the targeted header/claim rule can reject the token.
    """
    signing_input = f"{_b64url_json(header)}.{_b64url_json(claims)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(key.sign(signing_input))}"


EDDSA_HEADER = {"alg": "EdDSA", "typ": "JWT"}
B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _hs256_forge(header: dict, claims: dict, secret: bytes) -> str:
    signing_input = f"{_b64url_json(header)}.{_b64url_json(claims)}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode('ascii')}.{_b64url(sig)}"


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return generate_keypair()


@pytest.fixture
def other_key() -> Ed25519PrivateKey:
    return generate_keypair()


# ------------------------------------------------------------------ keys


def test_generate_keypair_returns_fresh_ed25519_private_keys():
    k1, k2 = generate_keypair(), generate_keypair()
    assert isinstance(k1, Ed25519PrivateKey)
    assert isinstance(k2, Ed25519PrivateKey)
    assert _raw_public_bytes(k1) != _raw_public_bytes(k2)


def test_saved_private_key_loads_back_as_the_same_key(tmp_path: Path, key):
    path = tmp_path / "agent.pem"
    save_private_key(key, path)
    loaded = load_private_key(path)
    assert isinstance(loaded, Ed25519PrivateKey)
    assert _raw_public_bytes(loaded) == _raw_public_bytes(key)
    # The loaded key must actually sign things the original public key accepts.
    token = sign_jwt(_claims(), loaded)
    assert _verify(token, key)["sub"] == "expense-bot"


def test_saved_private_key_is_pem(tmp_path: Path, key):
    path = tmp_path / "agent.pem"
    save_private_key(key, path)
    content = path.read_bytes()
    assert content.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert b"-----END PRIVATE KEY-----" in content


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are best-effort only")
def test_saved_private_key_is_not_readable_by_group_or_others(tmp_path: Path, key):
    path = tmp_path / "agent.pem"
    save_private_key(key, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0, oct(mode)


def test_load_private_key_rejects_a_non_ed25519_key(tmp_path: Path):
    # Key-type confusion: an EC key must never be accepted as our signing key.
    path = tmp_path / "ec.pem"
    ec_key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path)


def test_load_private_key_rejects_a_public_key_pem(tmp_path: Path, key):
    path = tmp_path / "pub.pem"
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path)


@pytest.mark.parametrize("content", [b"", b"not a key", b"-----BEGIN PRIVATE KEY-----\n"])
def test_load_private_key_rejects_garbage(tmp_path: Path, content: bytes):
    path = tmp_path / "garbage.pem"
    path.write_bytes(content)
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path)


def test_load_private_key_missing_file_raises(tmp_path: Path):
    with pytest.raises(OSError):
        load_private_key(tmp_path / "does-not-exist.pem")


# ------------------------------------------------------------------ JWK + thumbprint


def test_public_jwk_has_okp_ed25519_shape(key):
    jwk = public_jwk(key)
    assert isinstance(jwk, PublicJWK)
    assert jwk.kty == "OKP"
    assert jwk.crv == "Ed25519"
    assert len(jwk.x) == 43
    assert B64URL_NOPAD.match(jwk.x)
    assert "=" not in jwk.x
    assert _b64url_decode(jwk.x) == _raw_public_bytes(key)


def test_public_jwk_matches_rfc8037_example_key():
    priv = Ed25519PrivateKey.from_private_bytes(_b64url_decode(RFC8037_D))
    assert public_jwk(priv).x == RFC8037_X
    assert public_jwk(priv.public_key()).x == RFC8037_X


def test_public_jwk_never_contains_private_material():
    priv = Ed25519PrivateKey.from_private_bytes(_b64url_decode(RFC8037_D))
    jwk = public_jwk(priv)
    dumped = jwk.model_dump()
    assert "d" not in dumped
    assert RFC8037_D not in jwk.model_dump_json()


def test_jwk_thumbprint_of_rfc8037_example_key():
    assert jwk_thumbprint(PublicJWK(x=RFC8037_X)) == RFC8037_THUMBPRINT


def test_jwk_thumbprint_is_rfc7638_sha256_base64url_without_padding(key):
    jwk = public_jwk(key)
    # RFC 7638: required members only, lexicographic order, no whitespace.
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + jwk.x + '"}'
    expected = _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())
    tp = jwk_thumbprint(jwk)
    assert tp == expected
    assert len(tp) == 43
    assert "=" not in tp
    assert B64URL_NOPAD.match(tp)


def test_jwk_thumbprint_ignores_kid():
    # kid is not a required member; an attacker relabeling a key must not change its jkt.
    assert jwk_thumbprint(PublicJWK(x=RFC8037_X, kid="anything")) == RFC8037_THUMBPRINT


def test_jwk_thumbprint_differs_for_different_keys(key, other_key):
    assert jwk_thumbprint(public_jwk(key)) != jwk_thumbprint(public_jwk(other_key))


@pytest.mark.parametrize("flip", [0b01, 0b10, 0b11])
def test_jwk_thumbprint_rejects_non_canonical_x_encoding_of_the_same_key(flip):
    # 32 bytes = 256 bits, but 43 base64 chars carry 258: the last char has 2 unused low
    # bits. Flipping them gives a different string that lenient decoders read as the SAME
    # key, i.e. a second thumbprint for one key (a cnf.jkt binding bypass).
    last = B64URL_ALPHABET.index(RFC8037_X[-1])
    alt = RFC8037_X[:-1] + B64URL_ALPHABET[last ^ flip]
    assert alt != RFC8037_X
    assert _b64url_decode(alt) == _b64url_decode(RFC8037_X)  # precondition: same bytes
    with pytest.raises(ValueError):
        jwk_thumbprint(PublicJWK(x=alt))


@pytest.mark.parametrize(
    "bad_x",
    [
        '"' * 43,  # JSON injection into the RFC 7638 canonical form
        "=" * 43,
        RFC8037_X.replace("_", "/"),  # standard (non-url) alphabet, same bytes leniently
        " " + RFC8037_X[1:],
        _b64url(bytes(31)) + "=",  # 43 chars, but decodes to 31 bytes
    ],
)
def test_jwk_thumbprint_rejects_invalid_x(bad_x):
    assert len(bad_x) == 43  # passes the PublicJWK length check; thumbprint must still refuse
    with pytest.raises(ValueError):
        jwk_thumbprint(PublicJWK(x=bad_x))


@pytest.mark.parametrize("n_bytes", [31, 33])
def test_jwk_thumbprint_rejects_x_of_wrong_decoded_length(n_bytes):
    # model_construct skips pydantic validation: jwk_thumbprint must not rely on it.
    jwk = PublicJWK.model_construct(x=_b64url(bytes(range(n_bytes))))
    with pytest.raises(ValueError):
        jwk_thumbprint(jwk)


# ------------------------------------------------------------------ JWT sign / verify


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"scopes": ["files:read:/expenses/*"], "cnf": {"jkt": RFC8037_THUMBPRINT}},
        {"note": "café ✓ 日本"},  # unicode survives the round trip
    ],
)
def test_sign_verify_round_trips(key, extra):
    claims = _claims(**extra)
    token = sign_jwt(claims, key)
    assert isinstance(token, str)
    assert token.count(".") == 2
    assert _verify(token, key) == claims


def test_signed_token_header_uses_eddsa(key):
    token = sign_jwt(_claims(), key)
    assert jwt.get_unverified_header(token)["alg"] == "EdDSA"


def test_signed_token_interoperates_with_pyjwt(key):
    claims = _claims()
    token = sign_jwt(claims, key)
    decoded = jwt.decode(
        token,
        key.public_key(),
        algorithms=["EdDSA"],
        audience=STS_AUDIENCE,
        issuer=TOKEN_ISSUER,
    )
    assert decoded == claims


def test_sign_jwt_includes_extra_headers(key):
    jwk = public_jwk(key).model_dump(exclude_none=True)
    token = sign_jwt(_claims(), key, headers={"typ": "dpop+jwt", "jwk": jwk})
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "dpop+jwt"
    assert header["jwk"] == jwk
    assert header["alg"] == "EdDSA"


def test_sign_jwt_does_not_mutate_claims(key):
    claims = _claims()
    snapshot = dict(claims)
    sign_jwt(claims, key)
    assert claims == snapshot


@pytest.mark.parametrize(
    "headers",
    [
        {"alg": "none"},  # downgrade to unsigned
        {"alg": "HS256"},  # downgrade to HMAC
        {"alg": "EdDSA"},  # even the right value: alg is never caller-controlled
        {"ALG": "none"},
        {"Typ": "JWT"},
        {"crit": ["exp"]},
        {"b64": False},
        {"x5u": "https://evil.example/cert.pem"},
        {"jku": "https://evil.example/jwks.json"},
        {"x5c": ["MIIB"]},
        {"cty": "JWT"},
        {"typ": "dpop+jwt", "jku": "https://evil.example/jwks.json"},  # one bad key suffices
    ],
)
def test_sign_jwt_rejects_header_keys_outside_allowlist(key, headers):
    with pytest.raises(ValueError):
        sign_jwt(_claims(), key, headers=headers)


@pytest.mark.parametrize(
    "bad_jwk",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "d": RFC8037_D},  # private key leak
        {"kty": "oct", "k": "c2VjcmV0LWhtYWMta2V5"},  # symmetric key
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "x5u": "https://evil.example/k"},
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "alg": "HS256"},
        {"kty": "EC", "crv": "P-256", "x": RFC8037_X},
        {"kty": "OKP", "crv": "Ed25519", "x": "short"},
        {"kty": "OKP", "crv": "Ed25519"},  # no x
        json.dumps({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X}),  # a string, not an object
        [{"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X}],
    ],
)
def test_sign_jwt_rejects_jwk_header_that_is_not_a_public_jwk(key, bad_jwk):
    with pytest.raises(ValueError):
        sign_jwt(_claims(), key, headers={"typ": "dpop+jwt", "jwk": bad_jwk})


def test_sign_jwt_emits_valid_public_jwk_header_unchanged(key):
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": public_jwk(key).x}
    token = sign_jwt(_claims(), key, headers={"typ": "dpop+jwt", "jwk": jwk, "kid": "k1"})
    header = jwt.get_unverified_header(token)
    assert header["jwk"] == jwk  # public members only; no "kid": null added
    assert header["kid"] == "k1"
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "EdDSA"


# --- tampering


def test_tampered_payload_is_rejected(key):
    token = sign_jwt(_claims(scopes=["files:read:/expenses/*"]), key)
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))
    payload["scopes"] = ["bank:wire:*"]  # privilege escalation attempt
    forged = f"{header_b64}.{_b64url_json(payload)}.{sig_b64}"
    with pytest.raises(jwt.InvalidTokenError):
        _verify(forged, key)


def test_payload_with_extended_expiry_is_rejected(key):
    token = sign_jwt(_claims(), key)
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))
    payload["exp"] += 86400
    forged = f"{header_b64}.{_b64url_json(payload)}.{sig_b64}"
    with pytest.raises(jwt.InvalidTokenError):
        _verify(forged, key)


@pytest.mark.parametrize(
    "header_change",
    [
        {"kid": "attacker"},
        {"typ": "dpop+jwt"},
        {"crit": ["exp"]},
    ],
)
def test_tampered_header_is_rejected(key, header_change):
    token = sign_jwt(_claims(), key)
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    header.update(header_change)
    forged = f"{_b64url_json(header)}.{payload_b64}.{sig_b64}"
    with pytest.raises(jwt.InvalidTokenError):
        _verify(forged, key)


def test_spliced_payload_from_another_valid_token_is_rejected(key):
    low = sign_jwt(_claims(scopes=["files:read:/expenses/*"]), key)
    high = sign_jwt(_claims(scopes=["bank:wire:*"]), key)
    h1, _p1, s1 = low.split(".")
    _h2, p2, _s2 = high.split(".")
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{h1}.{p2}.{s1}", key)


def test_flipped_signature_byte_is_rejected(key):
    token = sign_jwt(_claims(), key)
    header_b64, payload_b64, sig_b64 = token.split(".")
    sig = bytearray(_b64url_decode(sig_b64))
    sig[0] ^= 0x01
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{header_b64}.{payload_b64}.{_b64url(bytes(sig))}", key)


def test_stripped_signature_is_rejected(key):
    token = sign_jwt(_claims(), key)
    header_b64, payload_b64, _sig = token.split(".")
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{header_b64}.{payload_b64}.", key)


# --- wrong key


def test_token_signed_by_another_key_is_rejected(key, other_key):
    token = sign_jwt(_claims(), other_key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_embedded_attacker_jwk_header_is_not_trusted(key, other_key):
    # The verifier must use the key it was given, never a key the token carries itself.
    attacker_jwk = public_jwk(other_key).model_dump(exclude_none=True)
    token = jwt.encode(_claims(), other_key, algorithm="EdDSA", headers={"jwk": attacker_jwk})
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_forged_and_expired_token_is_not_reported_as_merely_expired(key, other_key):
    # Signature is checked first; a forgery must not be reported as TOKEN_EXPIRED.
    token = sign_jwt(_claims(exp_offset=-600), other_key)
    with pytest.raises(jwt.InvalidTokenError) as exc_info:
        _verify(token, key)
    assert not isinstance(exc_info.value, jwt.ExpiredSignatureError)


# --- algorithm confusion


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE"])
def test_alg_none_token_is_rejected(key, alg):
    header = {"alg": alg, "typ": "JWT"}
    token = f"{_b64url_json(header)}.{_b64url_json(_claims())}."
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_alg_none_token_with_original_signature_is_rejected(key):
    token = sign_jwt(_claims(), key)
    _h, payload_b64, sig_b64 = token.split(".")
    forged = f"{_b64url_json({'alg': 'none', 'typ': 'JWT'})}.{payload_b64}.{sig_b64}"
    with pytest.raises(jwt.InvalidTokenError):
        _verify(forged, key)


@pytest.mark.parametrize("secret_kind", ["raw", "pem", "jwk_x"])
@pytest.mark.parametrize("alg", ["HS256", "EdDSA"])
def test_hmac_token_forged_with_public_key_as_secret_is_rejected(key, secret_kind, alg):
    # Classic alg-confusion attack: the public key is public, so an attacker can HMAC with it.
    pub = key.public_key()
    secret = {
        "raw": _raw_public_bytes(pub),
        "pem": pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "jwk_x": public_jwk(pub).x.encode("ascii"),
    }[secret_kind]
    token = _hs256_forge({"alg": alg, "typ": "JWT"}, _claims(), secret)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_es256_token_is_rejected(key):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    token = jwt.encode(_claims(), ec_key, algorithm="ES256")
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


# --- claims


def test_wrong_audience_is_rejected(key):
    # Token-type confusion: an STS token must not be accepted by the gateway.
    token = sign_jwt(_claims(aud=STS_AUDIENCE), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key, audience=GATEWAY_AUDIENCE)


def test_wrong_issuer_is_rejected(key):
    token = sign_jwt(_claims(iss="evil-issuer"), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


@pytest.mark.parametrize("missing", ["exp", "aud", "iss"])
def test_token_missing_required_claim_is_rejected(key, missing):
    claims = _claims()
    del claims[missing]
    token = sign_jwt(claims, key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_none_audience_or_issuer_is_not_a_wildcard(key):
    # Fail closed: a caller bug passing None must not skip the aud/iss checks.
    claims = _claims()
    del claims["aud"]
    del claims["iss"]
    token = sign_jwt(claims, key)
    with pytest.raises((jwt.InvalidTokenError, ValueError, TypeError)):
        verify_jwt(token, key.public_key(), None, None)


def test_expired_token_is_rejected_as_expired(key):
    token = sign_jwt(_claims(exp_offset=-60), key)
    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(token, key)


def test_token_exactly_at_expiry_is_rejected(key):
    # exp is the first second the token is NOT valid (RFC 7519 4.1.4), with no leeway.
    token = sign_jwt(_claims(exp_offset=0), key)
    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(token, key)


# --- validly signed but disallowed headers / claim shapes (only one check can reject)


def test_raw_signed_control_token_is_accepted(key):
    # Control: proves _sign_raw makes valid tokens, so the negatives below are meaningful.
    claims = _claims()
    assert _verify(_sign_raw(EDDSA_HEADER, claims, key), key) == claims


@pytest.mark.parametrize(
    "crit_header",
    [
        {"crit": ["exp"]},
        {"crit": ["x-aimfa-ext"], "x-aimfa-ext": True},
        {"crit": []},
    ],
)
def test_validly_signed_token_with_crit_header_is_rejected(key, crit_header):
    token = _sign_raw({**EDDSA_HEADER, **crit_header}, _claims(), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_validly_signed_token_with_b64_false_header_is_rejected(key):
    # Signature is valid over the normal base64url signing input; only "b64" is wrong.
    token = _sign_raw({**EDDSA_HEADER, "b64": False}, _claims(), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


def test_validly_signed_rfc7797_unencoded_payload_token_is_rejected(key):
    # RFC 7797: b64=false + crit=["b64"]; the payload is signed and sent unencoded.
    header_b64 = _b64url_json({**EDDSA_HEADER, "b64": False, "crit": ["b64"]})
    payload = json.dumps(_claims(), separators=(",", ":"))
    assert "." not in payload  # precondition: still splits into three segments
    signing_input = header_b64.encode("ascii") + b"." + payload.encode("utf-8")
    token = f"{header_b64}.{payload}.{_b64url(key.sign(signing_input))}"
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


@pytest.mark.parametrize("aud", [[STS_AUDIENCE], [STS_AUDIENCE, GATEWAY_AUDIENCE], []])
def test_validly_signed_token_with_list_audience_is_rejected(key, aud):
    # Our tokens have exactly one audience; a list could make one token valid at two services.
    token = _sign_raw(EDDSA_HEADER, _claims(aud=aud), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


@pytest.mark.parametrize(
    ("audience", "issuer"),
    [("", ""), ("", TOKEN_ISSUER), (STS_AUDIENCE, "")],
)
def test_empty_audience_or_issuer_raises_value_error(key, audience, issuer):
    # The token's claims match the empty expectations exactly, so only the argument
    # check can reject. Decision: ValueError (caller programming error).
    claims = _claims(aud=audience)
    claims["iss"] = issuer
    token = _sign_raw(EDDSA_HEADER, claims, key)
    with pytest.raises(ValueError):
        verify_jwt(token, key.public_key(), audience, issuer)


# --- token_use (token-type confusion, AGENTS.md rule 2)


@pytest.mark.parametrize(
    ("claim", "expected"),
    [("identity", "access"), ("access", "identity")],
)
def test_token_use_mismatch_is_rejected(key, claim, expected):
    # An identity token must never pass as an access token, and vice versa.
    token = sign_jwt(_claims(token_use=claim), key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use=expected)


@pytest.mark.parametrize("expected", ["identity", "access"])
def test_missing_token_use_claim_is_rejected_when_token_use_is_required(key, expected):
    claims = _claims()
    del claims["token_use"]
    token = sign_jwt(claims, key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use=expected)


@pytest.mark.parametrize(
    "variant",
    ["Access", "ACCESS", " access", "access ", "access\n", "", ["access"], None],
)
def test_token_use_case_whitespace_or_type_variant_is_rejected(key, variant):
    # Exact match only: no case folding, no trimming, no list membership.
    token = sign_jwt(_claims(token_use=variant), key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use="access")


@pytest.mark.parametrize("variant", ["Access", " access", "access "])
def test_token_use_variant_requested_by_caller_does_not_match(key, variant):
    token = sign_jwt(_claims(token_use="access"), key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use=variant)


@pytest.mark.parametrize(("use", "aud"), [("identity", STS_AUDIENCE), ("access", GATEWAY_AUDIENCE)])
def test_matching_token_use_passes(key, use, aud):
    claims = _claims(aud=aud, token_use=use)
    token = sign_jwt(claims, key)
    assert verify_jwt(token, key.public_key(), aud, TOKEN_ISSUER, token_use=use) == claims


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-jwt",
        "a.b",
        "a.b.c",
        "a.b.c.d",
        "....",
        "é.é.é",
        None,
        12345,
    ],
)
def test_malformed_token_is_rejected_cleanly(key, token):
    # Fail closed with the library's token error, not an unrelated crash.
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


# ------------------------------------------------------------------ measure

PROMPT = "You are an expense assistant. Only read /expenses."
MANIFEST = {"tools": [{"name": "read_file"}, {"name": "send_email"}]}
MODEL = "tamu-ai/gpt-4o"

AGENT_PY = b"def run():\n    return 'expense'\n"
TOOLS_PY = b"TOOLS = ['read_file', 'send_email']\n"


def _make_tree(root: Path) -> list[Path]:
    """agent.py at the root plus pkg/tools.py in a subdirectory (POSIX relpath 'pkg/...')."""
    (root / "pkg").mkdir(parents=True)
    a = root / "agent.py"
    b = root / "pkg" / "tools.py"
    a.write_bytes(AGENT_PY)
    b.write_bytes(TOOLS_PY)
    return [a, b]


@pytest.fixture
def agent_root(tmp_path: Path) -> Path:
    return tmp_path / "agent"


@pytest.fixture
def code_files(agent_root: Path) -> list[Path]:
    return _make_tree(agent_root)


def _m(paths, root, prompt=PROMPT, manifest=MANIFEST, model=MODEL) -> str:
    return measure(
        code_paths=paths, system_prompt=prompt, tool_manifest=manifest, model_id=model, root=root
    )


def test_measure_returns_lowercase_hex_sha256(code_files, agent_root):
    assert re.fullmatch(SHA256_HEX_PATTERN, _m(code_files, agent_root))


def test_measure_is_deterministic(code_files, agent_root):
    assert _m(code_files, agent_root) == _m(list(code_files), agent_root)


def test_measure_is_independent_of_code_path_order(code_files, agent_root):
    assert _m(code_files, agent_root) == _m(list(reversed(code_files)), agent_root)


def test_measure_accepts_str_and_path_equally(code_files, agent_root):
    assert _m(code_files, agent_root) == _m([str(p) for p in code_files], str(agent_root))


def test_measure_root_is_keyword_only_and_required(code_files, agent_root):
    with pytest.raises(TypeError):
        measure(code_files, PROMPT, MANIFEST, MODEL)  # root missing
    with pytest.raises(TypeError):
        measure(code_files, PROMPT, MANIFEST, MODEL, agent_root)  # root positional


def test_measure_is_the_same_for_the_same_tree_under_different_absolute_roots(tmp_path: Path):
    # Golden values are computed on one laptop and checked on another: the install
    # location must not leak into the fingerprint.
    root1 = tmp_path / "one" / "agent"
    files1 = _make_tree(root1)
    root2 = tmp_path / "two" / "deeper" / "elsewhere"
    shutil.copytree(root1, root2)
    files2 = [root2 / p.relative_to(root1) for p in files1]
    assert _m(files1, root1) == _m(files2, root2)


def test_measure_changes_when_two_files_swap_contents(code_files, agent_root):
    before = _m(code_files, agent_root)
    a, b = code_files
    a_bytes, b_bytes = a.read_bytes(), b.read_bytes()
    a.write_bytes(b_bytes)
    b.write_bytes(a_bytes)
    assert _m(code_files, agent_root) != before


@pytest.mark.parametrize("new_rel", ["pkg/tools2.py", "tools.py", "other/tools.py"])
def test_measure_changes_when_a_file_is_renamed_or_moved(code_files, agent_root, new_rel):
    before = _m(code_files, agent_root)
    src = code_files[1]
    dst = agent_root / new_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.rename(dst)
    assert dst.read_bytes() == TOOLS_PY  # same contents, different path
    assert _m([code_files[0], dst], agent_root) != before


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize("position", ["first", "last"])
def test_measure_changes_when_any_file_byte_changes(code_files, agent_root, which, position):
    before = _m(code_files, agent_root)
    target = code_files[which]
    data = bytearray(target.read_bytes())
    idx = 0 if position == "first" else len(data) - 1
    data[idx] ^= 0x01
    target.write_bytes(bytes(data))
    assert _m(code_files, agent_root) != before


def test_measure_changes_when_a_byte_is_appended(code_files, agent_root):
    before = _m(code_files, agent_root)
    code_files[0].write_bytes(code_files[0].read_bytes() + b"\n")
    assert _m(code_files, agent_root) != before


def test_measure_changes_when_a_file_is_added_or_removed(code_files, agent_root):
    full = _m(code_files, agent_root)
    assert _m(code_files[:1], agent_root) != full
    extra = agent_root / "backdoor.py"
    extra.write_bytes(b"import os\n")
    assert _m([*code_files, extra], agent_root) != full


def test_measure_detects_code_moved_between_files(agent_root):
    # Moving a line from the end of one file to the start of another changes behavior,
    # so it must change the fingerprint (no naive concatenation).
    agent_root.mkdir(parents=True)
    a, b = agent_root / "a.py", agent_root / "b.py"
    a.write_bytes(b"x = 1\ny = 2\n")
    b.write_bytes(b"z = 3\n")
    before = _m([a, b], agent_root)
    a.write_bytes(b"x = 1\n")
    b.write_bytes(b"y = 2\nz = 3\n")
    assert _m([a, b], agent_root) != before


def test_measure_missing_code_file_fails_closed(code_files, agent_root):
    with pytest.raises(OSError):
        _m([*code_files, agent_root / "missing.py"], agent_root)


def test_measure_empty_code_paths_is_rejected(agent_root):
    # An agent with no measured code would attest on prompt/manifest/model alone.
    agent_root.mkdir(parents=True)
    with pytest.raises(ValueError):
        _m([], agent_root)


@pytest.mark.parametrize("kind", ["sibling", "prefix_confusion", "dotdot", "dotdot_prefix"])
def test_measure_code_path_outside_root_is_rejected(code_files, agent_root, tmp_path, kind):
    # Every outside file EXISTS, so only the containment check can reject it.
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"evil = True\n")
    evil_dir = tmp_path / "agent-evil"  # shares the "agent" prefix with the root
    evil_dir.mkdir()
    (evil_dir / "x.py").write_bytes(b"evil = True\n")
    path = {
        "sibling": outside,
        "prefix_confusion": evil_dir / "x.py",
        "dotdot": f"{agent_root}/pkg/../../outside.py",  # unnormalized escape
        "dotdot_prefix": f"{agent_root}/../agent-evil/x.py",
    }[kind]
    with pytest.raises(ValueError):
        _m([*code_files, path], agent_root)


@pytest.mark.parametrize(
    "new_prompt",
    [
        PROMPT + " ",  # trailing whitespace
        PROMPT + "\n",
        PROMPT.replace("expenses", "engineering"),
        PROMPT.replace("a", "а", 1),  # Cyrillic homoglyph
        "",
    ],
)
def test_measure_changes_when_prompt_changes(code_files, agent_root, new_prompt):
    assert _m(code_files, agent_root, prompt=new_prompt) != _m(code_files, agent_root)


@pytest.mark.parametrize(
    "new_manifest",
    [
        {"tools": [{"name": "read_file"}]},
        {"tools": [{"name": "read_file"}, {"name": "send_email"}, {"name": "wire_money"}]},
        {"tools": [{"name": "read_file"}, {"name": "send_email", "external": True}]},
        {},
    ],
)
def test_measure_changes_when_manifest_changes(code_files, agent_root, new_manifest):
    assert _m(code_files, agent_root, manifest=new_manifest) != _m(code_files, agent_root)


@pytest.mark.parametrize("new_model", ["tamu-ai/gpt-4o-mini", "TAMU-AI/GPT-4O", MODEL + " ", ""])
def test_measure_changes_when_model_id_changes(code_files, agent_root, new_model):
    assert _m(code_files, agent_root, model=new_model) != _m(code_files, agent_root)


def test_measure_fields_are_unambiguously_separated(code_files, agent_root):
    # Shifting characters between the prompt and the model id must not collide.
    r = agent_root
    assert _m(code_files, r, prompt="ab", model="c") != _m(code_files, r, prompt="a", model="bc")
    assert _m(code_files, r, prompt="", model="x") != _m(code_files, r, prompt="x", model="")


# ------------------------------------------------------------------ canonical_json / sha256_hex


def test_canonical_json_sorts_keys_and_has_no_whitespace():
    obj = {"b": 1, "a": [3, 1, {"d": None, "c": True}]}
    assert canonical_json(obj) == b'{"a":[3,1,{"c":true,"d":null}],"b":1}'


def test_canonical_json_is_independent_of_insertion_order():
    assert canonical_json({"x": 1, "y": {"q": 2, "p": 3}}) == canonical_json(
        {"y": {"p": 3, "q": 2}, "x": 1}
    )


def test_canonical_json_keeps_whitespace_inside_values():
    assert canonical_json({"msg": "a b\tc"}) == b'{"msg":"a b\\tc"}'


def test_canonical_json_encodes_unicode_as_utf8_not_escapes():
    # CONTRACTS.md: ensure_ascii=False, encoded as UTF-8.
    assert canonical_json({"name": "café ✓"}) == '{"name":"café ✓"}'.encode()


def test_canonical_json_rejects_non_json_types():
    # No default= fallback: a silent str() could hash two different values identically.
    with pytest.raises(TypeError):
        canonical_json({"ts": datetime(2026, 11, 12, tzinfo=UTC)})


@pytest.mark.parametrize(
    "obj",
    [
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": float("-inf")},
        {"a": [1, {"b": float("nan")}]},
    ],
)
def test_canonical_json_rejects_nan_and_infinity(obj):
    # NaN/Infinity are not JSON; NaN != NaN also breaks "same input, same hash" reasoning.
    with pytest.raises(ValueError):
        canonical_json(obj)


def test_canonical_json_matches_contracts_formula_for_valid_json():
    obj = {"z": [1.5, -0.0, 10**20], "a": {"é": "✓", "n": None}, "m": 'q"uote'}
    expected = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canonical_json(obj) == expected.encode("utf-8")


def test_canonical_json_returns_bytes():
    assert isinstance(canonical_json({}), bytes)
    assert canonical_json({}) == b"{}"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ],
)
def test_sha256_hex_known_vectors(data, expected):
    assert sha256_hex(data) == expected


def test_sha256_hex_is_lowercase_64_hex():
    assert re.fullmatch(SHA256_HEX_PATTERN, sha256_hex(b"\x00" * 1000))
