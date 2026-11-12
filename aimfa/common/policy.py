"""Policy engine: turns an agent's tool call into a ``ResolvedAction`` and matches scopes.

Every gateway authorization decision and every STS escalation check rests on this module,
so it is deliberately strict and fails closed:

* ``resolve`` rejects unknown tools (ACTION_FORBIDDEN) and any argument it cannot fully
  understand (INVALID_ARGUMENTS). "Understand" means an allowlist: if a path, table name or
  email address contains anything unusual, it is rejected instead of guessed at.
* Scope matching is case-sensitive on every OS and only ``*`` is a wildcard (it may match
  ``/``). We do NOT use ``fnmatch``: on Windows it lowercases both sides, and it also gives
  ``?`` and ``[...]`` special meaning.
* The policy files are read with ``yaml.safe_load`` and validated strictly at load time, so
  a broken policy stops the service instead of silently allowing things.

The security logic lives in small pure functions (``normalize_path``, ``classify_recipient``,
``parse_scope``, ``glob_match`` ...) so it can be unit-tested without a server.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

import yaml

from aimfa.common.config import get_settings
from aimfa.common.models import ReasonCode, Tier

__all__ = [
    "Policy",
    "PolicyConfigError",
    "PolicyError",
    "ResolvedAction",
    "RoleSpec",
    "Scope",
    "ToolSpec",
    "classify_recipient",
    "glob_match",
    "normalize_path",
    "parse_scope",
    "scope_covers",
    "validate_table",
]

# Length caps: hostile input must fail fast and cleanly, never exhaust memory or CPU.
MAX_PATH_LENGTH = 1024
MAX_EMAIL_LENGTH = 254  # RFC 5321 path limit
# Scope pattern limits bound the cost of wildcard matching and keep scopes human-readable.
MAX_SCOPE_TARGET_LENGTH = 256
MAX_SCOPE_STARS = 4
MAX_SCOPE_LENGTH = 64 + MAX_SCOPE_TARGET_LENGTH

RECIPIENT_CLASS = "recipient_class"
INTERNAL = "internal"
EXTERNAL = "external"

# Services whose scope target comes from an argument, and what kind of value it is.
_PATH_SERVICE = "files"
_TABLE_SERVICE = "db"

# All regexes use explicit ASCII classes (no \w or \d, which match Unicode) and are used
# with fullmatch (``$`` would also accept a trailing newline).
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_TABLE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_SIMPLE_TARGET_RE = re.compile(r"[A-Za-z0-9_*-]{1,64}")
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*")

# Windows-canonical path segments. The resource server runs on Windows, where many
# spellings name a different file than the string says (see normalize_path).
_SEGMENT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._ -")
_PATTERN_SEGMENT_CHARS = _SEGMENT_CHARS | {"*"}
_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_ACTIONS_KEYS = frozenset({"internal_email_domains", "tools", "categories", "sensitive"})
_TOOL_KEYS = frozenset({"service", "verb", "target_arg", "target", "tier", "tiers", "args"})
_ROLES_KEYS = frozenset({"roles"})
_ROLE_KEYS = frozenset({"description", "allowed_scopes", "profile", "rate_limit_per_minute"})


# --------------------------------------------------------------------------------------
# Errors and value types
# --------------------------------------------------------------------------------------


class PolicyError(Exception):
    """A tool call was rejected. Callers map ``reason_code`` to an HTTP response.

    Messages never echo the rejected value: it is attacker-controlled and may be huge or
    contain data that should not end up in logs.
    """

    def __init__(self, reason_code: ReasonCode, message: str = "") -> None:
        super().__init__(message or reason_code.value)
        self.reason_code = reason_code
        self.message = message


class PolicyConfigError(ValueError):
    """policy/*.yaml is malformed. Raised at load time so a bad policy stops the service."""


class Scope(NamedTuple):
    """A parsed ``"<service>:<verb>:<target>"`` scope string."""

    service: str
    verb: str
    target: str


@dataclass(frozen=True)
class ToolSpec:
    """One tool from actions.yaml, validated."""

    name: str
    service: str
    verb: str
    args: frozenset[str]
    target_arg: str | None
    target: str | None
    tier: Tier | None
    tiers: dict[str, Tier]


@dataclass(frozen=True)
class RoleSpec:
    """One role from roles.yaml, validated."""

    name: str
    description: str
    allowed_scopes: tuple[str, ...]
    profile: tuple[str, ...]
    rate_limit_per_minute: int


@dataclass(frozen=True)
class ResolvedAction:
    """What a tool call actually does, in policy terms.

    ``args`` is a copy of the call's arguments with the target argument replaced by its
    normalized form. Callers must use it (not the raw args) for the real resource access,
    so the thing that was authorized is exactly the thing that is accessed.
    """

    service: str
    verb: str
    target: str
    tier: Tier
    category: str | None
    sensitive: bool
    tool: str
    args: dict[str, Any]


# --------------------------------------------------------------------------------------
# Pure security functions
# --------------------------------------------------------------------------------------


def _invalid(message: str) -> PolicyError:
    return PolicyError(ReasonCode.INVALID_ARGUMENTS, message)


def glob_match(pattern: str, text: str) -> bool:
    """Case-sensitive match where ``*`` matches any run of characters (including ``/``).

    Hand-written instead of fnmatch (case-folds on Windows, treats ``?``/``[`` as special)
    or a regex (``.*`` patterns can backtrack badly). Linear two-pointer algorithm.
    A ``*`` inside ``text`` is just a character; only a ``*`` in ``pattern`` is a wildcard.
    """
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and pattern[p] == text[t]:
            p += 1
            t += 1
        elif star != -1:
            # Let the last * swallow one more character and retry from there.
            mark += 1
            p, t = star + 1, mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _is_windows_canonical_segment(segment: str) -> bool:
    """True if Windows would open exactly the file this segment names, and nothing else.

    The resource server runs on Windows, where the string we authorize and the file that
    gets opened can differ. Each rule closes one such gap:
    * only ``[A-Za-z0-9._ -]``: this excludes ``:`` (``q3.csv::$DATA`` alternate streams,
      drive letters), ``~`` (8.3 short names like ``SECRE~1.TXT`` alias long names),
      ``\\`` (a separator on Windows), ``%`` (``%2e%2e`` decodes to ``..``), URL
      metacharacters ``? # ; & +`` (the path goes into the resource URL), control
      characters, and all non-ASCII (fullwidth dots/slashes, ``COM`` + superscript 1);
    * no leading space, no trailing dot or space: Win32 silently strips trailing dots and
      spaces, so ``leaked.env.`` opens ``leaked.env``;
    * no reserved device stem (``CON``, ``NUL``, ``COM1`` ... even as ``con.txt``): these
      open a device instead of a file.
    """
    if not segment or not all(ch in _SEGMENT_CHARS for ch in segment):
        return False
    if segment.startswith(" ") or segment.endswith((".", " ")):
        return False
    # Win32 strips trailing spaces from the stem, so "CON .txt" is still the console.
    stem = segment.split(".", 1)[0].rstrip(" ")
    return stem.upper() not in _RESERVED_DEVICE_NAMES


def normalize_path(raw: object) -> str:
    """Return the canonical absolute POSIX form of a file path, or raise INVALID_ARGUMENTS.

    Why each rule exists:
    * must be a string starting with ``/``: relative paths are resolved against some
      unknown working directory, so we cannot tell what they point at;
    * no ``..`` segment at all: ``/expenses/../engineering/x`` would pass a
      ``/expenses/*`` check as a raw string but reach /engineering;
    * normpath collapses ``//`` and ``/./``. POSIX normpath keeps exactly two leading
      slashes, so we strip them, otherwise ``//engineering/secrets.env`` would dodge the
      ``files:/engineering/secrets*`` sensitive rule;
    * every remaining segment must be Windows-canonical (see the helper above). This also
      rules out ``*``, so a concrete target never looks like a pattern.
    """
    if not isinstance(raw, str):
        raise _invalid("path must be a string")
    if not raw or len(raw) > MAX_PATH_LENGTH:
        raise _invalid("path is empty or too long")
    if not raw.startswith("/"):
        raise _invalid("path must be absolute")
    if ".." in raw.split("/"):
        raise _invalid("path must not contain '..'")
    normalized = "/" + posixpath.normpath(raw).lstrip("/")
    # Checked on the normalized value: that is the exact string we authorize and access.
    if normalized != "/" and not all(
        _is_windows_canonical_segment(seg) for seg in normalized[1:].split("/")
    ):
        raise _invalid("path contains a non-canonical segment")
    return normalized


def validate_table(raw: object) -> str:
    """A db table must be a plain identifier.

    The table name is placed in the resource URL (``/db/{table}``) and could reach SQL, so
    anything with ``/``, ``..``, quotes or ``;`` would be path traversal or injection.
    """
    if not isinstance(raw, str) or not _TABLE_RE.fullmatch(raw):
        raise _invalid("table must be a simple identifier")
    return raw


def classify_recipient(raw: object, internal_domains: frozenset[str]) -> str:
    """Return ``"internal"`` or ``"external"`` for one email address, or raise INVALID.

    Misclassifying an outsider as internal would downgrade a HIGH-tier send (human
    approval) to MEDIUM, so anything ambiguous is rejected rather than guessed:
    exactly one ``@`` (no recipient lists, no quoted local parts), ASCII-only
    (no homoglyphs), no control characters (no header injection), no trailing dot.
    The domain must be an EXACT member of ``internal_domains`` (case-insensitive, as DNS
    is), so ``acme.test.evil.com`` and ``sub.acme.test`` are external.
    """
    if not isinstance(raw, str) or not raw or len(raw) > MAX_EMAIL_LENGTH:
        raise _invalid("recipient must be a single email address")
    if raw.count("@") != 1:
        raise _invalid("recipient must contain exactly one '@'")
    local, domain = raw.split("@")
    if not _EMAIL_LOCAL_RE.fullmatch(local) or not _DOMAIN_RE.fullmatch(domain):
        raise _invalid("recipient is not a plain email address")
    # Safe to lower(): the regex guarantees ASCII, so no Unicode case-folding surprises.
    return INTERNAL if domain.lower() in internal_domains else EXTERNAL


def _is_valid_path_pattern(pattern: str) -> bool:
    """A files scope target: absolute, no empty/``.``/``..`` segments, safe characters.

    A pattern containing ``..`` or ``%2e`` is rejected outright so it can never be read
    as granting access outside the directory it names. Segments use the same character
    allowlist as concrete paths, plus ``*``.
    """
    if not pattern.startswith("/"):
        return False
    if pattern == "/":
        return True
    return all(
        seg not in ("", ".", "..") and all(ch in _PATTERN_SEGMENT_CHARS for ch in seg)
        for seg in pattern[1:].split("/")
    )


def _within_pattern_limits(target: str) -> bool:
    """At most 4 ``*`` and 256 characters: bounds matching cost and keeps scopes readable."""
    return 0 < len(target) <= MAX_SCOPE_TARGET_LENGTH and target.count("*") <= MAX_SCOPE_STARS


def parse_scope(scope: object) -> Scope | None:
    """Parse ``"<service>:<verb>:<target>"``; return None if malformed (grants nothing).

    Service and verb must be exact lowercase names (wildcards there are not part of the
    grammar, so ``*:*:*`` grants nothing). The target is validated per service and must
    be within the pattern limits.
    """
    if not isinstance(scope, str) or len(scope) > MAX_SCOPE_LENGTH:
        return None
    parts = scope.split(":", 2)
    if len(parts) != 3:
        return None
    service, verb, target = parts
    if not _NAME_RE.fullmatch(service) or not _NAME_RE.fullmatch(verb):
        return None
    if not _within_pattern_limits(target):
        return None
    if service == _PATH_SERVICE:
        ok = _is_valid_path_pattern(target)
    else:
        ok = _SIMPLE_TARGET_RE.fullmatch(target) is not None
    return Scope(service, verb, target) if ok else None


def _is_valid_resource_pattern(pattern: object, services: frozenset[str]) -> bool:
    """A category/sensitive pattern: ``<known service>:<target pattern>``.

    A typo such as ``file:/engineering/secrets*`` would otherwise match nothing, and the
    exfiltration rule would silently stop firing. So an unknown service fails the load.
    Files patterns may start with ``*`` (e.g. ``files:*.env`` = "any .env file").
    """
    if not isinstance(pattern, str):
        return False
    service, sep, target = pattern.partition(":")
    if not sep or service not in services or not _within_pattern_limits(target):
        return False
    if service == _PATH_SERVICE:
        return (
            target.startswith(("/", "*"))
            and ".." not in target.split("/")
            and all(ch in _PATTERN_SEGMENT_CHARS or ch == "/" for ch in target)
        )
    return _SIMPLE_TARGET_RE.fullmatch(target) is not None


def scope_covers(allowed: Scope, requested: Scope) -> bool:
    """True if every concrete target ``requested`` could match is also matched by ``allowed``.

    We match the allowed pattern against the requested pattern treated as literal text.
    That is sound: ``allowed`` has no literal ``*`` characters, so every ``*`` in
    ``requested`` must fall inside a region swallowed by one of allowed's wildcards, and
    that wildcard would equally swallow whatever the requested ``*`` expands to.
    """
    return (
        allowed.service == requested.service
        and allowed.verb == requested.verb
        and glob_match(allowed.target, requested.target)
    )


# --------------------------------------------------------------------------------------
# Loading and validating policy/*.yaml
# --------------------------------------------------------------------------------------


def _require(condition: object, message: str) -> None:
    if not condition:
        raise PolicyConfigError(message)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that also rejects duplicate mapping keys, at any nesting level.

    SafeLoader (never the full Loader, which runs ``!!python`` tags = code execution from a
    config file) is the base. On top of that, plain PyYAML silently keeps the LAST of two
    duplicate keys, so a second ``expense_reader:`` block further down roles.yaml would
    quietly replace the reviewed one. We refuse to load instead.
    """


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)  # expand "<<" merge keys so they are checked too
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError as exc:  # unhashable key, e.g. a list: reject, never ignore
            raise PolicyConfigError(f"line {key_node.start_mark.line + 1}: bad key") from exc
        if duplicate:
            raise PolicyConfigError(f"line {key_node.start_mark.line + 1}: duplicate key {key!r}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read_yaml(path: Path) -> dict[str, Any]:
    """Parse one policy file with the duplicate-rejecting SafeLoader."""
    with path.open(encoding="utf-8") as fh:
        loader = _UniqueKeySafeLoader(fh)
        try:
            doc = loader.get_single_data()
        finally:
            loader.dispose()
    _require(isinstance(doc, dict), f"{path.name}: top level must be a mapping")
    return doc


def _str_list(value: object, what: str) -> list[str]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{what} must be a list")
    _require(all(isinstance(v, str) and v for v in value), f"{what} must be non-empty strings")
    return list(value)


def _parse_tier(value: object, what: str) -> Tier:
    _require(isinstance(value, str) and value in {t.value for t in Tier}, f"{what}: bad tier")
    return Tier(str(value))


def _parse_tool(name: object, raw: object) -> ToolSpec:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise PolicyConfigError(f"bad tool name {name!r}")
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"tool {name}: must be a mapping")
    _require(set(raw) <= _TOOL_KEYS, f"tool {name}: unknown keys {set(raw) - _TOOL_KEYS}")

    service, verb = raw.get("service"), raw.get("verb")
    _require(isinstance(service, str) and _NAME_RE.fullmatch(service), f"tool {name}: service")
    _require(isinstance(verb, str) and _NAME_RE.fullmatch(verb), f"tool {name}: verb")
    args = _str_list(raw.get("args"), f"tool {name}: args")
    _require(len(set(args)) == len(args), f"tool {name}: duplicate args")
    _require(all(_NAME_RE.fullmatch(a) for a in args), f"tool {name}: bad arg name")

    _require(("target_arg" in raw) != ("target" in raw), f"tool {name}: need target_arg XOR target")
    target_arg: str | None = None
    target: str | None = None
    if "target_arg" in raw:
        target_arg = raw["target_arg"]
        _require(target_arg in args, f"tool {name}: target_arg must be one of args")
        # Only services whose targets we know how to validate may take one from an arg.
        _require(service in (_PATH_SERVICE, _TABLE_SERVICE), f"tool {name}: target_arg service")
    else:
        target = raw["target"]
        _require(isinstance(target, str), f"tool {name}: target must be a string")
        if target == RECIPIENT_CLASS:
            _require("to" in args, f"tool {name}: recipient_class needs a 'to' arg")
        else:
            _require(_SIMPLE_TARGET_RE.fullmatch(str(target)), f"tool {name}: bad fixed target")

    tier: Tier | None = None
    tiers: dict[str, Tier] = {}
    if target == RECIPIENT_CLASS:
        raw_tiers = raw.get("tiers")
        _require("tier" not in raw, f"tool {name}: use tiers, not tier")
        if not isinstance(raw_tiers, dict) or set(raw_tiers) != {INTERNAL, EXTERNAL}:
            raise PolicyConfigError(f"tool {name}: tiers must define exactly internal and external")
        tiers = {k: _parse_tier(v, f"tool {name}") for k, v in raw_tiers.items()}
    else:
        _require("tiers" not in raw, f"tool {name}: tiers only valid for recipient_class")
        tier = _parse_tier(raw.get("tier"), f"tool {name}")

    return ToolSpec(
        name=name,
        service=str(service),
        verb=str(verb),
        args=frozenset(args),
        target_arg=target_arg,
        target=target,
        tier=tier,
        tiers=tiers,
    )


def _parse_role(name: object, raw: object, categories: dict[str, list[str]]) -> RoleSpec:
    if not isinstance(name, str) or not name:
        raise PolicyConfigError(f"bad role name {name!r}")
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"role {name}: must be a mapping")
    _require(set(raw) <= _ROLE_KEYS, f"role {name}: unknown keys {set(raw) - _ROLE_KEYS}")

    description = raw.get("description", "")
    _require(isinstance(description, str), f"role {name}: description must be a string")
    scopes = _str_list(raw.get("allowed_scopes"), f"role {name}: allowed_scopes")
    for scope in scopes:
        _require(parse_scope(scope) is not None, f"role {name}: malformed scope {scope!r}")
    profile = _str_list(raw.get("profile"), f"role {name}: profile")
    for cat in profile:
        _require(cat in categories, f"role {name}: unknown profile category {cat!r}")
    rate = raw.get("rate_limit_per_minute")
    # bool is a subclass of int in Python: "rate_limit_per_minute: true" must not mean 1.
    if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
        raise PolicyConfigError(f"role {name}: rate_limit_per_minute must be a positive integer")
    return RoleSpec(
        name=name,
        description=str(description),
        allowed_scopes=tuple(scopes),
        profile=tuple(profile),
        rate_limit_per_minute=rate,
    )


# --------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------


class Policy:
    """The loaded, validated contents of policy/actions.yaml and policy/roles.yaml."""

    def __init__(
        self,
        tools: dict[str, ToolSpec],
        roles: dict[str, RoleSpec],
        internal_email_domains: frozenset[str],
        categories: dict[str, list[str]],
        sensitive: list[str],
    ) -> None:
        self._tools = dict(tools)
        self._roles = dict(roles)
        self._internal_domains = frozenset(internal_email_domains)
        self._categories = {k: list(v) for k, v in categories.items()}
        # Lowercased once here; see _is_sensitive for why this match ignores case.
        self._sensitive = [p.lower() for p in sensitive]
        # Role scopes were validated at load, so parse_scope cannot return None here.
        self._role_scopes: dict[str, list[Scope]] = {
            name: [s for s in map(parse_scope, spec.allowed_scopes) if s is not None]
            for name, spec in self._roles.items()
        }

    @classmethod
    def load(cls, policy_dir: Path | None = None) -> Policy:
        """Read ``<policy_dir>/actions.yaml`` and ``roles.yaml`` (default: Settings.policy_dir).

        Any structural problem raises (PolicyConfigError, yaml errors, OSError): a service
        must refuse to start on a broken policy rather than run with a partial one.
        """
        directory = Path(policy_dir) if policy_dir is not None else get_settings().policy_dir
        actions = _read_yaml(directory / "actions.yaml")
        roles_doc = _read_yaml(directory / "roles.yaml")

        _require(set(actions) == _ACTIONS_KEYS, f"actions.yaml: keys must be {_ACTIONS_KEYS}")
        domains = _str_list(actions["internal_email_domains"], "internal_email_domains")
        _require(all(_DOMAIN_RE.fullmatch(d) for d in domains), "internal_email_domains: bad")

        raw_tools = actions["tools"]
        _require(isinstance(raw_tools, dict), "actions.yaml: tools must be a mapping")
        tools = {str(n): _parse_tool(n, spec) for n, spec in raw_tools.items()}
        services = frozenset(spec.service for spec in tools.values())

        raw_categories = actions["categories"]
        _require(isinstance(raw_categories, dict), "actions.yaml: categories must be a mapping")
        categories: dict[str, list[str]] = {}
        for cat, patterns in raw_categories.items():
            _require(isinstance(cat, str) and _NAME_RE.fullmatch(cat), f"bad category {cat!r}")
            categories[str(cat)] = _str_list(patterns, f"category {cat}")
            for pattern in categories[str(cat)]:
                _require(
                    _is_valid_resource_pattern(pattern, services),
                    f"category {cat}: bad pattern {pattern!r}",
                )
        sensitive = _str_list(actions["sensitive"], "sensitive")
        for pattern in sensitive:
            _require(
                _is_valid_resource_pattern(pattern, services),
                f"sensitive: bad pattern {pattern!r}",
            )

        _require(set(roles_doc) == _ROLES_KEYS, "roles.yaml: top level must be 'roles'")
        raw_roles = roles_doc["roles"]
        _require(isinstance(raw_roles, dict), "roles.yaml: roles must be a mapping")
        roles = {str(n): _parse_role(n, spec, categories) for n, spec in raw_roles.items()}

        return cls(
            tools=tools,
            roles=roles,
            internal_email_domains=frozenset(d.lower() for d in domains),
            categories=categories,
            sensitive=sensitive,
        )

    # ---- tool calls --------------------------------------------------------------------

    def resolve(self, tool: str, args: Any) -> ResolvedAction:
        """Map a tool call to its scope family, normalized target, tier, category, sensitivity.

        Order matters (CONTRACTS pipeline step 5): an unknown or forbidden tool is
        ACTION_FORBIDDEN before its arguments are even looked at.
        """
        spec = self._tools.get(tool) if isinstance(tool, str) else None
        if spec is None:
            raise PolicyError(ReasonCode.ACTION_FORBIDDEN, "unknown tool")
        if spec.tier is Tier.FORBIDDEN:
            raise PolicyError(ReasonCode.ACTION_FORBIDDEN, "tool is forbidden by policy")

        # Exactly the declared args: an extra arg (bcc, from_account, task_id...) could be
        # forwarded to the resource and change what the call does without being authorized.
        if not isinstance(args, dict) or not all(isinstance(k, str) for k in args):
            raise _invalid("args must be an object with string keys")
        if set(args) != spec.args:
            raise _invalid(f"{spec.name} takes exactly: {', '.join(sorted(spec.args))}")

        normalized_args = dict(args)
        if spec.target_arg is not None:
            raw = args[spec.target_arg]
            if spec.service == _PATH_SERVICE:
                target = normalize_path(raw)
            elif spec.service == _TABLE_SERVICE:
                target = validate_table(raw)
            else:  # unreachable after load validation; fail closed anyway
                raise PolicyError(ReasonCode.ACTION_FORBIDDEN, "no validator for target")
            normalized_args[spec.target_arg] = target
            tier = spec.tier
        elif spec.target == RECIPIENT_CLASS:
            target = classify_recipient(args["to"], self._internal_domains)
            tier = spec.tiers.get(target)
        else:
            target = str(spec.target)
            tier = spec.tier

        if tier is None or tier is Tier.FORBIDDEN:
            raise PolicyError(ReasonCode.ACTION_FORBIDDEN, "action is forbidden by policy")

        return ResolvedAction(
            service=spec.service,
            verb=spec.verb,
            target=target,
            tier=tier,
            category=self._category_of(spec.service, target),
            sensitive=self._is_sensitive(spec.service, target),
            tool=spec.name,
            args=normalized_args,
        )

    def _category_of(self, service: str, target: str) -> str | None:
        """First category whose pattern matches ``<service>:<target>``; None = out of profile."""
        subject = f"{service}:{target}"
        for name, patterns in self._categories.items():
            if any(glob_match(p, subject) for p in patterns):
                return name
        return None

    def _is_sensitive(self, service: str, target: str) -> bool:
        """Sensitive reads feed the monitor's exfiltration-sequence rule.

        Case-INSENSITIVE on purpose: NTFS treats ``/engineering/SECRETS.ENV`` as the same
        file as ``secrets.env``, so odd casing must not dodge the rule. (Scopes and
        categories stay case-sensitive: there an odd casing simply matches nothing, which
        is the fail-closed direction.) Targets are ASCII-only, so ``lower()`` is exact.
        """
        subject = f"{service}:{target}".lower()
        return any(glob_match(p, subject) for p in self._sensitive)

    # ---- scopes and roles --------------------------------------------------------------

    def scope_allows(self, scopes: Any, action: ResolvedAction) -> bool:
        """True if at least one well-formed scope covers ``action``.

        Malformed scopes (and anything that is not a list of strings) grant nothing.
        """
        if not isinstance(scopes, list | tuple | set | frozenset):
            return False
        for raw in scopes:
            scope = parse_scope(raw)
            if (
                scope is not None
                and scope.service == action.service
                and scope.verb == action.verb
                and glob_match(scope.target, action.target)
            ):
                return True
        return False

    def role(self, name: str) -> RoleSpec:
        """Look up a role. Unknown names raise: a default role would be fail-open."""
        spec = self._roles.get(name) if isinstance(name, str) else None
        if spec is None:
            raise PolicyError(ReasonCode.INVALID_ARGUMENTS, "unknown role")
        return spec

    def role_permits(self, role_name: str, requested_scopes: Any) -> bool:
        """STS escalation check: EVERY requested scope must be covered by an allowed one.

        Unknown roles, empty requests and malformed scopes are simply "not permitted".
        """
        allowed = self._role_scopes.get(role_name) if isinstance(role_name, str) else None
        if allowed is None:
            return False
        if not isinstance(requested_scopes, list | tuple) or not requested_scopes:
            return False
        for raw in requested_scopes:
            requested = parse_scope(raw)
            if requested is None:
                return False
            if not any(scope_covers(a, requested) for a in allowed):
                return False
        return True
