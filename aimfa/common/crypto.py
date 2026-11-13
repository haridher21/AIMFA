"""Crypto helpers: Ed25519 keys, JWK thumbprints, EdDSA JWTs, measurements, hashing.

Everything in AIMFA that signs, verifies or fingerprints goes through this module, so the
security-sensitive choices (pinned algorithm, required claims, canonical encodings) are
made once, here. The functions are pure and context-free: they raise exceptions and let
the caller pick the ``ReasonCode``.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aimfa.common.models import SIGNING_ALG, PublicJWK

__all__ = [
    "action_hash",
    "canonical_json",
    "generate_keypair",
    "jwk_thumbprint",
    "load_private_key",
    "measure",
    "public_jwk",
    "save_private_key",
    "sha256_hex",
    "sign_jwt",
    "verify_jwt",
]

# Claims every verified token must carry (AGENTS.md rule 2). Without ``exp`` a token
# would live forever; without ``aud``/``iss`` PyJWT would silently skip those checks.
_REQUIRED_CLAIMS = ["exp", "aud", "iss"]
# Seconds of clock skew tolerated for ``iat`` when verify_jwt is given an injected ``now``.
_IAT_LEEWAY = 30


# ------------------------------------------------------------------ encoding helpers


def _b64url(data: bytes) -> str:
    """base64url without padding, as JOSE (RFC 7515 section 2) requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to one exact byte string (CONTRACTS.md "canonical JSON").

    Hashes and signatures must not depend on key order or whitespace, otherwise two
    parties could disagree about the same value. There is deliberately no ``default=``
    fallback: silently ``str()``-ing unknown types could make different values hash the
    same, so non-JSON types raise ``TypeError``. NaN/Infinity are not JSON (and NaN is not
    even equal to itself), so ``allow_nan=False`` makes them raise ``ValueError``; valid
    input still produces exactly the CONTRACTS.md bytes.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data`` (matches ``SHA256_HEX_PATTERN``)."""
    return hashlib.sha256(data).hexdigest()


def action_hash(agent_id: str, task_id: str, tool: str, args: dict[str, Any]) -> str:
    """Fingerprint of ONE exact action (CONTRACTS.md "Action hash").

    A human approves this hash, not a vague "send an email": the same agent, task, tool and
    (normalized) arguments must come back for the approval to be consumed. The gateway and
    the control plane both call this, so they cannot disagree about the rule.
    """
    return sha256_hex(
        canonical_json({"agent_id": agent_id, "task_id": task_id, "tool": tool, "args": args})
    )


# ------------------------------------------------------------------ keys


def generate_keypair() -> Ed25519PrivateKey:
    """Create a fresh Ed25519 private key (the OS CSPRNG is used by ``cryptography``)."""
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: str | os.PathLike[str]) -> None:
    """Write ``key`` as unencrypted PKCS#8 PEM, readable only by the owner (best effort).

    A new file is created with mode 0600 (subject to the umask, which can only remove
    bits). A file that already existed keeps its old mode until ``fchmod`` tightens it,
    which happens on the open descriptor BEFORE any key bytes are written, so the key is
    never readable by others through that path. ``O_NOFOLLOW`` refuses a symlink planted
    at ``path`` (it would redirect the key elsewhere). On Windows POSIX modes and
    ``O_NOFOLLOW``/``fchmod`` are unavailable, so this is best effort; ``keys/`` is
    git-ignored as a backstop.
    """
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("save_private_key expects an Ed25519PrivateKey")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)  # POSIX only
        | getattr(os, "O_BINARY", 0)  # Windows only: no newline translation
    )
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        # Best effort: os.fchmod does not exist on Windows (AttributeError), and some
        # filesystems refuse POSIX modes (OSError).
        with contextlib.suppress(AttributeError, OSError):
            os.fchmod(fh.fileno(), 0o600)
        fh.write(pem)


def load_private_key(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM, refusing any other key type.

    Accepting, say, an EC or RSA key here would let a misconfigured or swapped key file
    change which algorithm we sign with (key-type confusion). Errors never echo the file
    contents, so key material cannot leak into logs.
    """
    data = Path(path).read_bytes()  # OSError (e.g. missing file) propagates to the caller
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # ``from None`` drops the library's chained error, which may describe the input.
        raise ValueError(f"{Path(path).name}: not a readable unencrypted PEM key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{Path(path).name}: not an Ed25519 private key")
    return key


# ------------------------------------------------------------------ JWK + thumbprint


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> PublicJWK:
    """Return the public half of ``key`` as an RFC 8037 OKP JWK.

    Only the public ``x`` is ever emitted (never ``d``), so the result is safe to send
    over the wire or put in a token header.
    """
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("public_jwk expects an Ed25519 private or public key")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return PublicJWK(x=_b64url(raw))


def jwk_thumbprint(jwk: PublicJWK) -> str:
    """RFC 7638 SHA-256 thumbprint of ``jwk`` (base64url, no padding).

    The thumbprint is a stable name for a key, used as ``cnf.jkt`` to bind tokens to the
    agent's key (DPoP). Only the required members ``crv``, ``kty`` and ``x`` are hashed,
    in lexicographic order with no whitespace, so relabeling a key (e.g. a new ``kid``)
    cannot change its identity.
    """
    if not isinstance(jwk, PublicJWK):
        raise TypeError("jwk_thumbprint expects a PublicJWK")
    # Re-checked here because PublicJWK.model_construct() skips pydantic validation.
    if jwk.kty != "OKP" or jwk.crv != "Ed25519":
        raise ValueError("only OKP/Ed25519 keys are supported")
    _check_ed25519_x(jwk.x)
    members = {"crv": jwk.crv, "kty": jwk.kty, "x": jwk.x}
    return _b64url(hashlib.sha256(canonical_json(members)).digest())


_B64URL_43 = re.compile(r"[A-Za-z0-9_-]{43}")


def _check_ed25519_x(x: object) -> None:
    """Require ``x`` to be the ONE canonical base64url encoding of a 32-byte key.

    43 base64 characters carry 258 bits but a key has 256, so the last character has 2
    spare bits. Lenient decoders ignore them, which gives up to four strings (and four
    thumbprints) for the same key: an attacker could then dodge a ``cnf.jkt`` binding or
    a key denylist. We also refuse the standard ``+/`` alphabet, padding, whitespace and
    any character that could break out of the JSON in the RFC 7638 hash input.
    """
    if not isinstance(x, str) or not _B64URL_43.fullmatch(x):
        raise ValueError("jwk x must be 43 base64url characters (no padding)")
    raw = base64.urlsafe_b64decode(x + "=")
    if len(raw) != 32 or _b64url(raw) != x:
        raise ValueError("jwk x is not the canonical encoding of a 32-byte Ed25519 key")


# ------------------------------------------------------------------ JWT sign / verify


def sign_jwt(
    claims: dict[str, Any],
    key: Ed25519PrivateKey,
    headers: dict[str, Any] | None = None,
) -> str:
    """Sign ``claims`` as a compact EdDSA JWT.

    ``headers`` may only set ``typ``, ``jwk`` and ``kid`` (see ``_checked_sign_headers``);
    ``alg`` is always EdDSA and never caller-controlled.
    """
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("sign_jwt expects an Ed25519PrivateKey")
    if not isinstance(claims, dict):
        raise TypeError("claims must be a dict")
    extra = _checked_sign_headers(headers)
    return jwt.encode(dict(claims), key, algorithm=SIGNING_ALG, headers=extra or None)


_ALLOWED_SIGN_HEADERS = frozenset({"typ", "jwk", "kid"})


def _checked_sign_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Allowlist the extra JWS header members we are willing to sign.

    An allowlist, not a denylist: PyJWT lets a header ``alg`` override the algorithm
    (``none``/HMAC downgrade), ``crit``/``b64`` change how the token is parsed, and
    ``jku``/``x5u``/``x5c`` tell naive verifiers to fetch or trust a different key. None of
    these are needed, so anything outside ``typ``/``jwk``/``kid`` is refused. A ``jwk``
    must be a valid public Ed25519 JWK, so a private key (``d``) or a symmetric key can
    never be published in a token header.
    """
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ValueError("headers must be a dict")
    unknown = set(headers) - _ALLOWED_SIGN_HEADERS
    if unknown:
        raise ValueError(f"header members not allowed: {sorted(map(str, unknown))}")
    checked: dict[str, Any] = {}
    for name in ("typ", "kid"):
        if name in headers:
            if not isinstance(headers[name], str) or not headers[name]:
                raise ValueError(f"header {name!r} must be a non-empty string")
            checked[name] = headers[name]
    if "jwk" in headers:
        checked["jwk"] = _checked_header_jwk(headers["jwk"])
    return checked


def _checked_header_jwk(value: object) -> dict[str, Any]:
    """Validate a ``jwk`` header as a public Ed25519 JWK and return its public members."""
    if isinstance(value, PublicJWK):
        jwk = value
    elif isinstance(value, dict):
        try:
            jwk = PublicJWK.model_validate(value)
        except ValueError:
            # ``from None``: pydantic's message echoes the input, which may hold a private ``d``.
            raise ValueError("jwk header is not a public Ed25519 JWK") from None
    else:
        raise ValueError("jwk header must be a JSON object")
    jwk_thumbprint(jwk)  # same strict, canonical-``x`` check the verifiers rely on
    return jwk.model_dump(exclude_none=True)


def _require_str(value: object, name: str) -> str:
    """Fail closed on a missing expected value: ``None`` must never mean "skip the check"."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _checked_header(token: str) -> dict[str, Any]:
    """Read the (still unverified) header and reject anything but plain EdDSA.

    This is independent of PyJWT's own ``algorithms=`` pin, so a library default change
    cannot reopen ``alg=none`` / HS256 confusion. ``crit`` is rejected because we
    implement no JWS extensions (RFC 7515 4.1.11 says unknown critical ones must fail).
    """
    try:
        header = jwt.get_unverified_header(token)
    except (ValueError, TypeError):
        raise jwt.DecodeError("malformed token header") from None
    alg = header.get("alg")
    if not isinstance(alg, str) or alg != SIGNING_ALG:
        raise jwt.InvalidAlgorithmError("only EdDSA tokens are accepted")
    if "crit" in header or "b64" in header:
        raise jwt.InvalidTokenError("JWS extensions (crit/b64) are not accepted")
    return header


def verify_jwt(
    token: str,
    public_key: Ed25519PublicKey,
    audience: str,
    issuer: str,
    *,
    token_use: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify an EdDSA JWT and return its claims, or raise ``jwt.InvalidTokenError``.

    Checks, in order: header ``alg`` is EdDSA; signature under ``public_key`` (never a
    key carried in the token); ``exp``/``aud``/``iss`` present and correct with zero
    leeway; and, if ``token_use`` is given, an exact ``token_use`` match. Expiry raises
    ``jwt.ExpiredSignatureError`` only after the signature checked out, so a forgery is
    never reported as merely expired.

    ``now`` (Unix seconds) lets a service with an injected clock decide expiry by ITS
    clock instead of the machine's, so TTL logic is testable without sleeping. When given,
    ``exp`` is enforced here with the same zero leeway (never skipped).
    """
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("verify_jwt expects an Ed25519PublicKey")
    _require_str(audience, "audience")
    _require_str(issuer, "issuer")
    if token_use is not None:
        _require_str(token_use, "token_use")
    if not isinstance(token, str) or not token:
        raise jwt.DecodeError("token must be a non-empty string")

    _checked_header(token)
    claims = jwt.decode(
        token,
        public_key,
        algorithms=[SIGNING_ALG],
        audience=audience,
        issuer=issuer,
        leeway=0,
        options={
            "verify_signature": True,
            # With an injected clock PyJWT's wall-clock exp/iat checks are replaced below.
            "verify_exp": now is None,
            "verify_iat": now is None,
            "verify_aud": True,
            "verify_iss": True,
            "require": _REQUIRED_CLAIMS,
            # aud must be exactly our string, not a list that happens to contain it.
            "strict_aud": True,
        },
    )
    if now is not None:
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, int | float) or exp <= now:
            raise jwt.ExpiredSignatureError("signature has expired")
        # A token dated in the future (beyond a little clock skew) is not valid yet.
        iat = claims.get("iat")
        if iat is not None and (
            isinstance(iat, bool) or not isinstance(iat, int | float) or iat > now + _IAT_LEEWAY
        ):
            raise jwt.ImmatureSignatureError("token issued in the future")

    # Token-type confusion: an identity token must never pass as an access token.
    # Exact string match only (no case folding, trimming or list membership).
    if token_use is not None:
        actual = claims.get("token_use")
        if not isinstance(actual, str) or actual != token_use:
            raise jwt.InvalidTokenError("token_use claim does not match")
    return claims


# ------------------------------------------------------------------ measurement


def measure(
    code_paths: Iterable[str | os.PathLike[str]],
    system_prompt: str,
    tool_manifest: Any,
    model_id: str,
    *,
    root: str | os.PathLike[str],
) -> str:
    """Fingerprint an agent ("what it IS") as a hex SHA-256.

    Each code file is recorded as a ``[path relative to root, sha256 of contents]`` pair;
    the sorted pairs are combined with the prompt, manifest and model id via
    ``canonical_json``. Why each piece:

    * per-file hashes (not concatenation): moving bytes between files changes the result;
    * relative paths: swapping two files' contents or renaming a file changes behavior
      (imports, entry point), so it must change the result, while the install location
      (the absolute ``root``) must not, so goldens are portable between laptops;
    * sorting: the result does not depend on the order paths were listed;
    * JSON framing: bytes cannot shift between fields to forge a collision.

    Fails closed: a missing file raises ``OSError``; an empty list, a duplicate, or a
    path that resolves outside ``root`` (``..``, symlinks, look-alike siblings such as
    ``agent-evil/``) raises ``ValueError``.
    """
    if isinstance(code_paths, str | bytes | os.PathLike):
        raise TypeError("code_paths must be a list of paths, not a single path")
    if not isinstance(system_prompt, str):
        raise TypeError("system_prompt must be a str")
    if not isinstance(model_id, str):
        raise TypeError("model_id must be a str")

    # strict=True: a missing root is a configuration error, not "measure nothing".
    root_dir = Path(root).resolve(strict=True)
    files: list[list[str]] = []
    seen: set[str] = set()
    for p in code_paths:
        rel = _relative_to_root(Path(p), root_dir)
        if rel in seen:
            raise ValueError(f"code path listed twice: {rel}")
        seen.add(rel)
        files.append([rel, sha256_hex((root_dir / rel).read_bytes())])
    if not files:
        # An agent with no measured code would attest on prompt/manifest/model alone.
        raise ValueError("code_paths must not be empty")

    document = {
        "files": sorted(files),
        "system_prompt": system_prompt,
        "tool_manifest": tool_manifest,
        "model_id": model_id,
    }
    return sha256_hex(canonical_json(document))


def _relative_to_root(path: Path, root_dir: Path) -> str:
    """Return ``path``'s POSIX path relative to ``root_dir``, or raise ``ValueError``.

    Both sides are fully resolved (``..`` collapsed, symlinks followed) BEFORE the
    containment check, and the check is component-wise (``is_relative_to``), so neither
    ``agent/../outside.py`` nor a sibling named ``agent-evil`` passes a string-prefix test.
    The caller reads the file via the same resolved location it authorized.
    """
    resolved = path.resolve()
    if not resolved.is_relative_to(root_dir) or resolved == root_dir:
        raise ValueError(f"code path is outside the agent root: {path}")
    return resolved.relative_to(root_dir).as_posix()
