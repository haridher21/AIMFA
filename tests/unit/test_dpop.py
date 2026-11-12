"""Tests for aimfa/common/dpop.py (ROADMAP T1.2: DPoP proofs, RFC 9449 simplified).

Decisions under test: ``typ`` is exactly "dpop+jwt", ``alg`` exactly "EdDSA"; the header jwk is a
strict ``PublicJWK`` (kty/crv must be present); claims are not coerced; ``htm``/``htu`` are exact
string compares; the ``iat`` window is inclusive; ``ath`` is required iff an access token is given;
``expected_jkt=""`` is a mismatch. Check order: MALFORMED -> BAD_SIGNATURE -> KEY_MISMATCH -> HTM ->
HTU -> STALE -> ATH -> REPLAY, and a jti is recorded only when every other check passed.
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

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aimfa.common import crypto, dpop
from aimfa.common.models import GATEWAY_AUDIENCE, TOKEN_ISSUER, PublicJWK, ReasonCode

DPoPError = dpop.DPoPError
ReplayCache = dpop.ReplayCache
make_proof = dpop.make_proof
verify_proof = dpop.verify_proof

generate_keypair = crypto.generate_keypair
jwk_thumbprint = crypto.jwk_thumbprint
public_jwk = crypto.public_jwk
sign_jwt = crypto.sign_jwt

NOW = 1_800_000_000  # fixed injected clock (Unix seconds)
MAX_AGE = 60
HTU = "http://127.0.0.1:8100/tool"  # gateway endpoint
TOKEN_HTU = "http://127.0.0.1:8000/token"  # control plane STS endpoint
ACCESS_TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJleHBlbnNlLWJvdCJ9.ZmFrZS1zaWduYXR1cmU"
OTHER_ACCESS_TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJvdGhlci1ib3QifQ.ZmFrZS1zaWduYXR1cmU"

_DROP = object()  # sentinel: remove this header member / claim


def _id(value: Any) -> str:
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
    sig = signer.sign(f"{h_b64}.{p_b64}".encode("ascii")) if signer is not None else b""
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


# ------------------------------------------------------------------ make_proof


def test_dpop_error_carries_its_reason_code():
    err = DPoPError(ReasonCode.DPOP_REPLAY)
    assert isinstance(err, Exception) and err.reason_code == ReasonCode.DPOP_REPLAY


def test_make_proof_header_claims_and_no_private_material(key):
    proof = make_proof(key, "POST", HTU, now=NOW)
    header, claims, _sig = _split(proof)
    assert (header["typ"], header["alg"]) == ("dpop+jwt", "EdDSA")
    assert header["jwk"] == _jwk_dict(key) and "d" not in header["jwk"]
    assert (claims["htm"], claims["htu"], claims["iat"]) == ("POST", HTU, NOW)
    assert type(claims["iat"]) is int and len(claims["jti"]) >= 16
    assert "ath" not in claims
    raw_d = _b64url(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    assert raw_d not in json.dumps(header) + json.dumps(claims)


def test_make_proof_with_access_token_sets_ath_and_never_embeds_the_token(key):
    proof = make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW)
    assert _split(proof)[1]["ath"] == _ath(ACCESS_TOKEN)
    assert ACCESS_TOKEN not in proof


# ------------------------------------------------------------------ valid proofs


def test_valid_proof_passes_and_returns_the_proof_public_jwk(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    jwk = _verify(proof, cache=cache, expected_jkt=jwk_thumbprint(public_jwk(key)))
    assert isinstance(jwk, PublicJWK) and jwk.x == public_jwk(key).x


def test_hand_built_proof_passes(key):
    # Control: the forging helper builds valid proofs, so negatives fail for the right reason.
    assert _verify(_proof(key)).x == public_jwk(key).x
    assert _verify(_proof(key, jti="a" * 16)).x == public_jwk(key).x  # min jti length


# ------------------------------------------------------------------ DPOP_MALFORMED


@pytest.mark.parametrize("proof", ["", None, 12345], ids=_id)
def test_non_jwt_input_is_malformed(proof):
    _expect(ReasonCode.DPOP_MALFORMED, proof)


@pytest.mark.parametrize(
    ("header_raw", "payload_raw"),
    [(b"not json", None), (None, b"not json")],
)
def test_header_or_payload_that_is_not_a_json_object_is_malformed(key, header_raw, payload_raw):
    h = _b64url(header_raw) if header_raw is not None else _b64url_json(_header(key))
    p = _b64url(payload_raw) if payload_raw is not None else _b64url_json(_payload())
    _expect(ReasonCode.DPOP_MALFORMED, _sign_segments(h, p, key))


@pytest.mark.parametrize("typ", ["JWT", None, _DROP], ids=_id)
def test_wrong_or_missing_typ_is_malformed(key, typ):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"typ": typ}))


@pytest.mark.parametrize("alg", ["none", None, _DROP], ids=_id)
def test_wrong_or_missing_alg_is_malformed(key, alg):
    # Signed with the right key but the header lies about alg: the verifier pins EdDSA.
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"alg": alg}))


def test_unsigned_alg_none_proof_is_malformed(key):
    proof = _forge(_header(key, alg="none"), _payload(), signer=None)
    assert proof.endswith(".")
    _expect(ReasonCode.DPOP_MALFORMED, proof)


def test_hs256_proof_forged_with_public_key_as_secret_is_malformed(key):
    h, p = _b64url_json(_header(key, alg="HS256")), _b64url_json(_payload())
    secret = public_jwk(key).x.encode("ascii")
    sig = hmac.new(secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    _expect(ReasonCode.DPOP_MALFORMED, f"{h}.{p}.{_b64url(sig)}")


_JWK_VARIANTS: list[tuple[str, Callable[[dict], Any]]] = [
    ("missing", lambda j: _DROP),
    ("kty_EC", lambda j: {**j, "kty": "EC"}),
    # PublicJWK defaults kty/crv, so model validation alone would accept these omissions.
    ("missing_kty", lambda j: {k: v for k, v in j.items() if k != "kty"}),
    ("extra_member_use", lambda j: {**j, "use": "sig"}),
]


@pytest.mark.parametrize("mutate", [m for _, m in _JWK_VARIANTS], ids=[n for n, _ in _JWK_VARIANTS])
def test_missing_or_invalid_jwk_is_malformed(key, mutate):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, header={"jwk": mutate(_jwk_dict(key))}))


def test_private_jwk_with_d_is_malformed_and_d_is_not_echoed(key):
    d = _b64url(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    err = _expect(
        ReasonCode.DPOP_MALFORMED, _proof(key, header={"jwk": {**_jwk_dict(key), "d": d}})
    )
    assert d not in str(err) and d not in repr(err)


def test_access_token_presented_as_proof_is_malformed(key):
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


@pytest.mark.parametrize("claim", ["jti", "iat"])
def test_missing_required_claim_is_malformed(key, claim):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, **{claim: _DROP}))


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("jti", "a" * 15),  # DPoPProofClaims: min_length=16
        ("iat", str(NOW)),  # numeric string: no coercion
        ("iat", NOW + 0.5),  # fractional float
    ],
    ids=_id,
)
def test_claim_with_wrong_type_or_shape_is_malformed(key, claim, value):
    _expect(ReasonCode.DPOP_MALFORMED, _proof(key, **{claim: value}))


# ------------------------------------------------------------------ DPOP_BAD_SIGNATURE


def test_proof_signed_by_a_different_key_than_its_jwk_is_bad_signature(key, other_key):
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, _proof(key, signer=other_key))


@pytest.mark.parametrize(
    ("field", "value"),
    [("htu", HTU), ("jti", "f" * 32)],  # retarget, refresh, dodge replay cache
)
def test_tampered_payload_is_bad_signature(key, field, value):
    original = make_proof(key, "GET", TOKEN_HTU, now=NOW - 30)
    h, p, s = original.split(".")
    claims = json.loads(_b64url_decode(p))
    claims[field] = value
    forged = f"{h}.{_b64url_json(claims)}.{s}"
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, forged, htm=claims["htm"], htu=claims["htu"])


def test_swapped_jwk_header_is_bad_signature(key, other_key):
    _h, p, s = make_proof(key, "POST", HTU, now=NOW).split(".")
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{_b64url_json(_header(other_key))}.{p}.{s}")


def test_flipped_or_empty_signature_is_bad_signature(key):
    h, p, s = make_proof(key, "POST", HTU, now=NOW).split(".")
    sig = bytearray(_b64url_decode(s))
    sig[0] ^= 0x01
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{h}.{p}.{_b64url(bytes(sig))}")
    _expect(ReasonCode.DPOP_BAD_SIGNATURE, f"{h}.{p}.")


# ------------------------------------------------------------------ DPOP_KEY_MISMATCH


def test_valid_proof_from_another_key_is_key_mismatch(key, other_key):
    # Stolen access token + attacker's own key: well-formed, correctly signed, wrong key.
    proof = make_proof(other_key, "POST", HTU, now=NOW)
    _expect(ReasonCode.DPOP_KEY_MISMATCH, proof, expected_jkt=jwk_thumbprint(public_jwk(key)))


def test_empty_expected_jkt_is_key_mismatch_not_skipped(key):
    _expect(ReasonCode.DPOP_KEY_MISMATCH, make_proof(key, "POST", HTU, now=NOW), expected_jkt="")


def test_near_miss_expected_jkt_is_key_mismatch(key):
    jkt = jwk_thumbprint(public_jwk(key))
    for variant in (jkt + "=", jkt.swapcase(), jkt[:-1]):
        _expect(
            ReasonCode.DPOP_KEY_MISMATCH,
            make_proof(key, "POST", HTU, now=NOW),
            expected_jkt=variant,
        )


# ------------------------------------------------------------------ DPOP_HTM_MISMATCH / HTU


@pytest.mark.parametrize(("proof_htm", "expected_htm"), [("GET", "POST"), ("post", "POST")])
def test_wrong_method_is_htm_mismatch(key, proof_htm, expected_htm):
    _expect(ReasonCode.DPOP_HTM_MISMATCH, _proof(key, htm=proof_htm), htm=expected_htm)


@pytest.mark.parametrize(
    "proof_htu",
    [
        "https://127.0.0.1:8100/tool",  # scheme
        "http://127.0.0.1:8000/tool",  # port
        TOKEN_HTU,  # a valid proof for a different endpoint
    ],
    ids=_id,
)
def test_wrong_url_is_htu_mismatch(key, proof_htu):
    _expect(ReasonCode.DPOP_HTU_MISMATCH, _proof(key, htu=proof_htu))


@pytest.mark.parametrize("suffix", ["?", "#frag"], ids=_id)
def test_url_with_query_or_fragment_is_htu_mismatch(key, suffix):
    _expect(ReasonCode.DPOP_HTU_MISMATCH, _proof(key, htu=HTU + suffix))


# ------------------------------------------------------------------ DPOP_STALE


@pytest.mark.parametrize("iat", [NOW - MAX_AGE - 1, NOW + MAX_AGE + 1], ids=_id)
def test_iat_outside_window_is_stale(key, iat):
    # Too old (replay of a captured proof) or pre-dated (would outlive max_age).
    _expect(ReasonCode.DPOP_STALE, _proof(key, iat=iat))


@pytest.mark.parametrize("offset", [-MAX_AGE, MAX_AGE])
def test_iat_exactly_at_max_age_boundary_passes(key, offset):
    assert _verify(_proof(key, iat=NOW + offset)).x == public_jwk(key).x


# ------------------------------------------------------------------ DPOP_ATH_MISMATCH


def test_missing_or_other_token_ath_is_ath_mismatch(key):
    _expect(
        ReasonCode.DPOP_ATH_MISMATCH,
        make_proof(key, "POST", HTU, now=NOW),  # no access_token -> no ath
        access_token=ACCESS_TOKEN,
    )
    proof = make_proof(key, "POST", HTU, access_token=OTHER_ACCESS_TOKEN, now=NOW)
    err = _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=ACCESS_TOKEN)
    for secret in (ACCESS_TOKEN, OTHER_ACCESS_TOKEN):
        assert secret not in str(err) and secret not in repr(err)


@pytest.mark.parametrize(
    "ath",
    [
        _ath(ACCESS_TOKEN) + "=",  # padded
        hashlib.sha256(ACCESS_TOKEN.encode("ascii")).hexdigest(),  # hex, not base64url
        ACCESS_TOKEN,  # the raw token instead of its hash
        "",
    ],
    ids=["padded", "hex", "raw_token", "empty"],
)
def test_near_miss_ath_is_ath_mismatch(key, ath):
    _expect(ReasonCode.DPOP_ATH_MISMATCH, _proof(key, ath=ath), access_token=ACCESS_TOKEN)


def test_ath_present_without_an_access_token_is_ath_mismatch(key):
    proof = make_proof(key, "POST", HTU, access_token=ACCESS_TOKEN, now=NOW)
    _expect(ReasonCode.DPOP_ATH_MISMATCH, proof, access_token=None)


def test_empty_access_token_still_requires_ath(key):
    # "" is not None: fail closed instead of skipping the binding check.
    _expect(ReasonCode.DPOP_ATH_MISMATCH, make_proof(key, "POST", HTU, now=NOW), access_token="")


# ------------------------------------------------------------------ DPOP_REPLAY


def test_same_proof_twice_is_replay_even_a_second_later(key, cache):
    proof = make_proof(key, "POST", HTU, now=NOW)
    _verify(proof, cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache, now=NOW + 1)


def test_same_jti_for_a_different_url_or_iat_is_replay(key, cache):
    jti = _jti()
    _verify(_proof(key, jti=jti, htu=HTU), cache=cache)
    _expect(ReasonCode.DPOP_REPLAY, _proof(key, jti=jti, htu=TOKEN_HTU), cache=cache, htu=TOKEN_HTU)
    _expect(ReasonCode.DPOP_REPLAY, _proof(key, jti=jti, iat=NOW + 5), cache=cache, now=NOW + 5)


def test_replay_is_rejected_at_the_last_second_the_proof_is_fresh(key, cache):
    # A proof pre-dated by max_age stays fresh until now + 2*max_age; hence TTL = 2 x max_age.
    proof = _proof(key, iat=NOW + MAX_AGE)
    _verify(proof, cache=cache, now=NOW)
    _expect(ReasonCode.DPOP_REPLAY, proof, cache=cache, now=NOW + 2 * MAX_AGE)


def test_replay_cache_forgets_jti_after_ttl(key, cache):
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
    if kind == "htu":
        return _proof(victim, jti=jti, htu=TOKEN_HTU), {}
    if kind == "stale":
        return _proof(victim, jti=jti, iat=NOW - 10 * MAX_AGE), {}
    if kind == "ath":
        return _proof(victim, jti=jti, ath=_ath(OTHER_ACCESS_TOKEN)), {"access_token": ACCESS_TOKEN}
    return _proof(victim, jti=jti, header={"typ": "JWT"}), {}  # malformed


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("malformed", ReasonCode.DPOP_MALFORMED),
        ("bad_signature", ReasonCode.DPOP_BAD_SIGNATURE),
        ("stale", ReasonCode.DPOP_STALE),
        ("ath", ReasonCode.DPOP_ATH_MISMATCH),
    ],
)
def test_rejected_proof_does_not_burn_the_jti(key, other_key, cache, kind, reason):
    # If failed proofs were recorded, an attacker could pre-submit junk carrying a victim's jti
    # and make the victim's real request fail as a "replay".
    jti = _jti()
    bad, kwargs = _failing_variant(kind, victim=key, attacker=other_key, jti=jti)
    _expect(reason, bad, cache=cache, **kwargs)
    good = _proof(key, jti=jti, ath=_ath(ACCESS_TOKEN))
    jwk = _verify(
        good, cache=cache, access_token=ACCESS_TOKEN, expected_jkt=jwk_thumbprint(public_jwk(key))
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
    # Nothing about an unauthenticated proof is reported before its signature is checked, and
    # the replay cache is only consulted for otherwise-valid proofs.
    proof, kwargs = build(key, other_key, cache)
    _expect(reason, proof, cache=cache, **kwargs)
