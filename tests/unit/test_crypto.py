"""Tests for aimfa/common/crypto.py (ROADMAP T1.1: crypto helpers).

Interface: keys are ``cryptography`` Ed25519 objects; ``verify_jwt`` raises PyJWT's
``jwt.InvalidTokenError`` (``ExpiredSignatureError`` for expiry), requires exp/aud/iss,
uses zero leeway and, when ``token_use`` is given, requires an exact match (rule 2).
``measure`` binds each file to its relative path under a required keyword-only ``root``.
``jwk_thumbprint`` needs a strict 32-byte canonical ``x``. ``sign_jwt`` only allows the
``typ``/``jwk``/``kid`` headers. ``canonical_json`` forbids non-JSON types and NaN.
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

B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
EDDSA_HEADER = {"alg": "EdDSA", "typ": "JWT"}


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
    """Validly EdDSA-sign any header/claims so only the targeted rule can reject it."""
    signing_input = f"{_b64url_json(header)}.{_b64url_json(claims)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(key.sign(signing_input))}"


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


def test_generate_save_and_load_keypair_round_trip(tmp_path: Path, key):
    assert _raw_public_bytes(generate_keypair()) != _raw_public_bytes(generate_keypair())
    path = tmp_path / "agent.pem"
    save_private_key(key, path)
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    loaded = load_private_key(path)
    assert _raw_public_bytes(loaded) == _raw_public_bytes(key)
    assert _verify(sign_jwt(_claims(), loaded), key)["sub"] == "expense-bot"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are best-effort only")
def test_saved_private_key_is_not_readable_by_group_or_others(tmp_path: Path, key):
    path = tmp_path / "agent.pem"
    save_private_key(key, path)
    assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0


def test_load_private_key_rejects_non_ed25519_and_public_key_pem(tmp_path: Path, key):
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    for i, content in enumerate([ec_pem, pub_pem, b"", b"not a key"]):
        path = tmp_path / f"bad{i}.pem"
        path.write_bytes(content)
        with pytest.raises((ValueError, TypeError)):
            load_private_key(path)
    with pytest.raises(OSError):
        load_private_key(tmp_path / "does-not-exist.pem")


# ------------------------------------------------------------------ JWK + thumbprint


def test_public_jwk_shape_rfc8037_vector_and_no_private_material():
    priv = Ed25519PrivateKey.from_private_bytes(_b64url_decode(RFC8037_D))
    jwk = public_jwk(priv)
    assert (jwk.kty, jwk.crv, jwk.x) == ("OKP", "Ed25519", RFC8037_X)
    assert public_jwk(priv.public_key()).x == RFC8037_X
    assert "d" not in jwk.model_dump()
    assert RFC8037_D not in jwk.model_dump_json()


def test_jwk_thumbprint_matches_rfc_vector_ignores_kid_and_differs_per_key(key, other_key):
    assert jwk_thumbprint(PublicJWK(x=RFC8037_X)) == RFC8037_THUMBPRINT
    assert jwk_thumbprint(PublicJWK(x=RFC8037_X, kid="anything")) == RFC8037_THUMBPRINT
    jwk = public_jwk(key)
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + jwk.x + '"}'
    assert jwk_thumbprint(jwk) == _b64url(hashlib.sha256(canonical.encode()).digest())
    assert jwk_thumbprint(jwk) != jwk_thumbprint(public_jwk(other_key))


def test_jwk_thumbprint_rejects_non_canonical_x_encoding_of_the_same_key():
    # The last of 43 chars has 2 unused bits; flipping them is a second string for one key
    # (a cnf.jkt binding bypass).
    last = B64URL_ALPHABET.index(RFC8037_X[-1])
    alt = RFC8037_X[:-1] + B64URL_ALPHABET[last ^ 0b01]
    assert _b64url_decode(alt) == _b64url_decode(RFC8037_X)
    with pytest.raises(ValueError):
        jwk_thumbprint(PublicJWK(x=alt))


@pytest.mark.parametrize(
    "bad_x",
    [
        '"' * 43,  # JSON injection into the RFC 7638 canonical form
        _b64url(bytes(31)) + "=",  # 43 chars, but decodes to 31 bytes
    ],
)
def test_jwk_thumbprint_rejects_invalid_x(bad_x):
    with pytest.raises(ValueError):
        jwk_thumbprint(PublicJWK(x=bad_x))


# ------------------------------------------------------------------ JWT sign / verify


def test_sign_verify_round_trip_headers_and_interop(key):
    claims = _claims(scopes=["files:read:/expenses/*"], note="café ✓")
    snapshot = dict(claims)
    token = sign_jwt(claims, key)
    assert claims == snapshot  # not mutated
    assert jwt.get_unverified_header(token)["alg"] == "EdDSA"
    assert _verify(token, key) == claims
    decoded = jwt.decode(
        token, key.public_key(), algorithms=["EdDSA"], audience=STS_AUDIENCE, issuer=TOKEN_ISSUER
    )
    assert decoded == claims


@pytest.mark.parametrize(
    "headers",
    [
        {"alg": "none"},  # downgrade to unsigned
        {"typ": "dpop+jwt", "x5u": "https://evil.example/cert.pem"},  # one bad key suffices
    ],
)
def test_sign_jwt_rejects_header_keys_outside_allowlist(key, headers):
    with pytest.raises(ValueError):
        sign_jwt(_claims(), key, headers=headers)


@pytest.mark.parametrize(
    "bad_jwk",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "d": RFC8037_D},  # private key leak
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "x5u": "https://evil.example/k"},
    ],
)
def test_sign_jwt_rejects_jwk_header_that_is_not_a_public_jwk(key, bad_jwk):
    with pytest.raises(ValueError):
        sign_jwt(_claims(), key, headers={"typ": "dpop+jwt", "jwk": bad_jwk})


# --- tampering


def _split(token: str) -> tuple[str, str, str]:
    h, p, s = token.split(".")
    return h, p, s


def test_tampered_payload_is_rejected(key):
    h, p, s = _split(sign_jwt(_claims(scopes=["files:read:/expenses/*"]), key))
    payload = json.loads(_b64url_decode(p))
    payload["scopes"] = ["bank:wire:*"]  # privilege escalation attempt
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{h}.{_b64url_json(payload)}.{s}", key)


def test_spliced_payload_from_another_valid_token_is_rejected(key):
    h1, _p1, s1 = _split(sign_jwt(_claims(scopes=["files:read:/expenses/*"]), key))
    _h2, p2, _s2 = _split(sign_jwt(_claims(scopes=["bank:wire:*"]), key))
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{h1}.{p2}.{s1}", key)


def test_flipped_or_stripped_signature_is_rejected(key):
    h, p, s = _split(sign_jwt(_claims(), key))
    sig = bytearray(_b64url_decode(s))
    sig[0] ^= 0x01
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{h}.{p}.{_b64url(bytes(sig))}", key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(f"{h}.{p}.", key)


# --- wrong key


def test_token_signed_by_another_key_is_rejected(key, other_key):
    with pytest.raises(jwt.InvalidTokenError):
        _verify(sign_jwt(_claims(), other_key), key)


def test_embedded_attacker_jwk_header_is_not_trusted(key, other_key):
    attacker_jwk = public_jwk(other_key).model_dump(exclude_none=True)
    token = jwt.encode(_claims(), other_key, algorithm="EdDSA", headers={"jwk": attacker_jwk})
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


# --- algorithm confusion


@pytest.mark.parametrize("alg", ["none"])
def test_alg_none_token_is_rejected(key, alg):
    token = f"{_b64url_json({'alg': alg, 'typ': 'JWT'})}.{_b64url_json(_claims())}."
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


@pytest.mark.parametrize("secret_kind", ["raw"])
def test_hmac_token_forged_with_public_key_as_secret_is_rejected(key, secret_kind):
    pub = key.public_key()
    secret = {
        "raw": _raw_public_bytes(pub),
        "pem": pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    }[secret_kind]
    token = _hs256_forge({"alg": "HS256", "typ": "JWT"}, _claims(), secret)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


# --- claims


def test_wrong_audience_is_rejected(key):
    token = sign_jwt(_claims(aud=STS_AUDIENCE), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key, audience=GATEWAY_AUDIENCE)


def test_wrong_issuer_is_rejected(key):
    with pytest.raises(jwt.InvalidTokenError):
        _verify(sign_jwt(_claims(iss="evil-issuer"), key), key)


@pytest.mark.parametrize("missing", ["exp", "aud"])
def test_token_missing_required_claim_is_rejected(key, missing):
    claims = _claims()
    del claims[missing]
    with pytest.raises(jwt.InvalidTokenError):
        _verify(sign_jwt(claims, key), key)


def test_none_audience_or_issuer_is_not_a_wildcard(key):
    claims = _claims()
    del claims["aud"]
    del claims["iss"]
    with pytest.raises((jwt.InvalidTokenError, ValueError, TypeError)):
        verify_jwt(sign_jwt(claims, key), key.public_key(), None, None)


@pytest.mark.parametrize("exp_offset", [-60, 0])  # expired, and exactly at expiry (no leeway)
def test_expired_token_is_rejected_as_expired(key, exp_offset):
    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(sign_jwt(_claims(exp_offset=exp_offset), key), key)


@pytest.mark.parametrize("extra_header", [{"crit": ["exp"]}, {"b64": False}])
def test_validly_signed_token_with_crit_or_b64_header_is_rejected(key, extra_header):
    token = _sign_raw({**EDDSA_HEADER, **extra_header}, _claims(), key)
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


@pytest.mark.parametrize("aud", [[STS_AUDIENCE]])
def test_validly_signed_token_with_list_audience_is_rejected(key, aud):
    # Our tokens have exactly one audience; a list could make one token valid at two services.
    with pytest.raises(jwt.InvalidTokenError):
        _verify(_sign_raw(EDDSA_HEADER, _claims(aud=aud), key), key)


@pytest.mark.parametrize(("audience", "issuer"), [("", ""), (STS_AUDIENCE, "")])
def test_empty_audience_or_issuer_raises_value_error(key, audience, issuer):
    claims = _claims(aud=audience)
    claims["iss"] = issuer
    token = _sign_raw(EDDSA_HEADER, claims, key)
    with pytest.raises(ValueError):
        verify_jwt(token, key.public_key(), audience, issuer)


# --- token_use (token-type confusion)


@pytest.mark.parametrize(("claim", "expected"), [("identity", "access"), ("access", "identity")])
def test_token_use_mismatch_is_rejected(key, claim, expected):
    token = sign_jwt(_claims(token_use=claim), key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use=expected)


def test_missing_token_use_claim_is_rejected_when_required(key):
    claims = _claims()
    del claims["token_use"]
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(
            sign_jwt(claims, key), key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use="access"
        )


@pytest.mark.parametrize("variant", ["Access", ["access"]])
def test_token_use_case_whitespace_or_type_variant_is_rejected(key, variant):
    token = sign_jwt(_claims(token_use=variant), key)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, key.public_key(), STS_AUDIENCE, TOKEN_ISSUER, token_use="access")


@pytest.mark.parametrize(("use", "aud"), [("identity", STS_AUDIENCE), ("access", GATEWAY_AUDIENCE)])
def test_matching_token_use_passes(key, use, aud):
    claims = _claims(aud=aud, token_use=use)
    token = sign_jwt(claims, key)
    assert verify_jwt(token, key.public_key(), aud, TOKEN_ISSUER, token_use=use) == claims


@pytest.mark.parametrize("token", ["", None])
def test_malformed_token_is_rejected_cleanly(key, token):
    with pytest.raises(jwt.InvalidTokenError):
        _verify(token, key)


# ------------------------------------------------------------------ measure

PROMPT = "You are an expense assistant. Only read /expenses."
MANIFEST = {"tools": [{"name": "read_file"}, {"name": "send_email"}]}
MODEL = "tamu-ai/gpt-4o"
AGENT_PY = b"def run():\n    return 'expense'\n"
TOOLS_PY = b"TOOLS = ['read_file', 'send_email']\n"


def _make_tree(root: Path) -> list[Path]:
    (root / "pkg").mkdir(parents=True)
    a, b = root / "agent.py", root / "pkg" / "tools.py"
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


def test_measure_is_hex_sha256_deterministic_and_order_independent(code_files, agent_root):
    m = _m(code_files, agent_root)
    assert re.fullmatch(SHA256_HEX_PATTERN, m)
    assert m == _m(list(reversed(code_files)), agent_root)
    assert m == _m([str(p) for p in code_files], str(agent_root))


def test_measure_is_the_same_for_the_same_tree_under_different_absolute_roots(tmp_path: Path):
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


def test_measure_changes_when_a_file_is_renamed(code_files, agent_root):
    before = _m(code_files, agent_root)
    dst = agent_root / "pkg" / "tools2.py"
    code_files[1].rename(dst)
    assert _m([code_files[0], dst], agent_root) != before


def test_measure_changes_when_a_byte_changes_is_appended_or_a_file_added(code_files, agent_root):
    before = _m(code_files, agent_root)
    target = code_files[0]
    data = bytearray(target.read_bytes())
    data[-1] ^= 0x01
    target.write_bytes(bytes(data))
    assert _m(code_files, agent_root) != before
    target.write_bytes(AGENT_PY)
    assert _m(code_files, agent_root) == before
    extra = agent_root / "backdoor.py"
    extra.write_bytes(b"import os\n")
    assert _m([*code_files, extra], agent_root) != before
    assert _m(code_files[:1], agent_root) != before


def test_measure_missing_file_and_empty_code_paths_fail_closed(code_files, agent_root):
    with pytest.raises(OSError):
        _m([*code_files, agent_root / "missing.py"], agent_root)
    with pytest.raises(ValueError):
        _m([], agent_root)


@pytest.mark.parametrize("kind", ["sibling", "prefix_confusion", "dotdot"])
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
        "dotdot": f"{agent_root}/pkg/../../outside.py",
    }[kind]
    with pytest.raises(ValueError):
        _m([*code_files, path], agent_root)


def test_measure_changes_when_prompt_manifest_or_model_changes(code_files, agent_root):
    base = _m(code_files, agent_root)
    assert _m(code_files, agent_root, prompt=PROMPT + " ") != base
    assert _m(code_files, agent_root, prompt=PROMPT.replace("a", "а", 1)) != base  # homoglyph
    assert _m(code_files, agent_root, manifest={"tools": [{"name": "read_file"}]}) != base
    assert _m(code_files, agent_root, model="tamu-ai/gpt-4o-mini") != base


# ------------------------------------------------------------------ canonical_json / sha256_hex


def test_canonical_json_sorts_keys_no_whitespace_utf8_and_matches_contract():
    assert canonical_json({"b": 1, "a": [3, 1, {"d": None, "c": True}]}) == (
        b'{"a":[3,1,{"c":true,"d":null}],"b":1}'
    )
    assert canonical_json({"msg": "a b\tc"}) == b'{"msg":"a b\\tc"}'
    assert canonical_json({"name": "café ✓"}) == '{"name":"café ✓"}'.encode()
    obj = {"z": [1.5, -0.0, 10**20], "a": {"é": "✓", "n": None}, "m": 'q"uote'}
    expected = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canonical_json(obj) == expected.encode("utf-8")


def test_canonical_json_rejects_non_json_types():
    with pytest.raises(TypeError):
        canonical_json({"ts": datetime(2026, 11, 12, tzinfo=UTC)})


@pytest.mark.parametrize("obj", [{"x": float("nan")}])
def test_canonical_json_rejects_nan_and_infinity(obj):
    with pytest.raises(ValueError):
        canonical_json(obj)


def test_sha256_hex_known_vector():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
