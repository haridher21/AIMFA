"""T1.4 Policy engine: tests written from docs/ROADMAP.md, docs/CONTRACTS.md and policy/*.yaml.

The policy engine turns an agent's tool call into a ``ResolvedAction`` (service, verb, scope
target, tier, category, sensitive) and decides whether scope strings cover it. Every gateway
authorization decision and every STS escalation check rests on it, so most tests here are
negative tests that pin the exact ``ReasonCode`` (or a ``False``) for hostile input.

Interface assumptions (the ROADMAP leaves these open; this is the simplest reading):
  * ``from aimfa.common.policy import Policy, PolicyError, ResolvedAction``.
  * ``Policy.load(policy_dir: Path) -> Policy`` is a classmethod reading
    ``<policy_dir>/roles.yaml`` and ``<policy_dir>/actions.yaml``.
  * ``resolve``, ``scope_allows``, ``role_permits`` and ``role`` are **methods** on the
    loaded ``Policy`` instance.
  * ``PolicyError`` is an ``Exception`` exposing ``.reason_code: ReasonCode``
    (like ``DPoPError(ReasonCode.X)`` in aimfa/common/README.md).
  * ``ResolvedAction`` exposes attributes ``service, verb, target, tier, category, sensitive``:
    ``tier`` compares equal to ``Tier`` members (``Tier`` is a StrEnum), ``category`` is the
    single matching category key from actions.yaml or ``None``, ``sensitive`` is a bool.
  * ``role(name)`` returns an object with attributes ``allowed_scopes``, ``profile`` and
    ``rate_limit_per_minute``; an unknown role raises ``PolicyError`` or ``LookupError``.
  * ``role_permits(role_name: str, requested_scopes: list[str]) -> bool``. Malformed or
    unknown inputs may either return ``False`` or raise ``PolicyError``/``LookupError``:
    both count as "not permitted".
  * Scope and category matching is case-SENSITIVE on every OS (no ``fnmatch.fnmatch``,
    which lowercases on Windows); only ``*`` is a wildcard and it may match ``/``.
    ``sensitive`` is the exception: see security-review decision 2 below.
  * Email domain classification is case-insensitive (DNS is) but otherwise EXACT membership
    in ``internal_email_domains`` (CONTRACTS: "recipient domain is in internal_email_domains"),
    so subdomains such as ``sub.acme.test`` are external.
  * Non-canonical but harmless spellings (``/expenses//q3.csv``, ``/expenses/``) may be either
    normalized to the canonical path or rejected with INVALID_ARGUMENTS. They must never be
    authorized in their raw form.
  * Percent-encoded, NFKC-lookalike, backslash or NUL-containing paths are rejected with
    INVALID_ARGUMENTS: if anything downstream decodes them, they become traversal.
  * ``query_db``/``delete_table`` table names must be simple identifiers; anything with a
    ``/``, ``..``, ``;``, quote, NUL or empty string is INVALID_ARGUMENTS (the table is placed
    in the resource URL path ``/db/{table}``).

Security-review decisions (T1.4 follow-up; these are now part of the spec):
  1. Windows-canonical paths. After normalization, every path segment may contain only
     ``[A-Za-z0-9._ -]``; a segment must not start with a space or end with "." or a space;
     a segment whose stem (text before the first ".") case-insensitively equals a Windows
     reserved device name (CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9) is rejected. All of
     these are INVALID_ARGUMENTS. Why: the resource server runs on Windows, where
     ``q3.csv::$DATA``, ``leaked.env.``, ``SECRE~1.TXT`` and ``CON`` all name something
     other than what the policy string says, so the authorized string and the file actually
     opened could differ.
  2. ``sensitive`` is computed case-INSENSITIVELY (``/engineering/SECRETS.ENV`` is the same
     file on NTFS, and the exfil rule must not be dodged by casing). Scope matching and
     categories stay case-sensitive (fail closed: an odd casing simply matches nothing).
  3. Scope pattern limits: a scope whose target has more than 4 ``*`` or is longer than 256
     characters is rejected (role_permits -> not permitted; scope_allows -> grants nothing).
     This bounds wildcard-matching cost.
  4. Policy loading fails closed with ``PolicyConfigError`` (accessed as
     ``aimfa.common.policy.PolicyConfigError``) on: duplicate YAML keys, a category or
     sensitive pattern whose service prefix is unknown, an unknown tier, an unknown key on a
     tool, or a tool without ``args``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import aimfa.common.policy as policy_mod
from aimfa.common.config import POLICY_DIR
from aimfa.common.models import ReasonCode, Tier
from aimfa.common.policy import Policy, PolicyError, ResolvedAction

INVALID = ReasonCode.INVALID_ARGUMENTS
FORBIDDEN = ReasonCode.ACTION_FORBIDDEN


# --------------------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def policy() -> Policy:
    """The real, checked-in policy/ directory."""
    return Policy.load(POLICY_DIR)


def _read(path: str) -> dict:
    return {"path": path}


def _email(to: str) -> dict:
    return {"to": to, "subject": "Q3 summary", "body": "See attached numbers."}


def _wire() -> dict:
    return {"to_account": "ACME-VENDOR-001", "amount": 125.50, "memo": "invoice 42"}


def _resolve_or_code(policy: Policy, tool: str, args) -> ResolvedAction | ReasonCode:
    """Return the ResolvedAction, or the ReasonCode of the PolicyError it raised.

    Any exception other than PolicyError propagates and fails the test: hostile input must
    produce a clean, typed denial, never a crash (a crash would be a 500, not a 403/422).
    """
    try:
        return policy.resolve(tool, args)
    except PolicyError as exc:
        return exc.reason_code


def _permits(policy: Policy, role: str, scopes: list[str]) -> bool:
    """role_permits, treating a typed rejection as 'not permitted'."""
    try:
        return policy.role_permits(role, scopes) is True
    except (PolicyError, LookupError):
        return False


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def test_load_returns_policy_from_real_policy_dir(policy):
    assert isinstance(policy, Policy)


def test_policy_error_is_an_exception_carrying_reason_code(policy):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("no_such_tool", {})
    assert isinstance(exc_info.value, Exception)
    assert exc_info.value.reason_code == FORBIDDEN


def _write_policy(dir_: Path, actions_yaml: str, roles_yaml: str) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "actions.yaml").write_text(actions_yaml, encoding="utf-8")
    (dir_ / "roles.yaml").write_text(roles_yaml, encoding="utf-8")
    return dir_


_MIN_ROLES = """
roles:
  nuker:
    description: test role
    allowed_scopes: ["db:delete:*"]
    profile: []
    rate_limit_per_minute: 1
"""

_FORBIDDEN_ACTIONS = """
internal_email_domains: ["acme.test"]
tools:
  nuke_everything:
    service: db
    verb: delete
    target: "*"
    tier: forbidden
    args: [confirm]
categories: {}
sensitive: []
"""


def test_load_uses_the_given_directory_not_a_global(tmp_path):
    """A policy loaded from another dir must not silently know the real tools."""
    pol = Policy.load(_write_policy(tmp_path / "pol", _FORBIDDEN_ACTIONS, _MIN_ROLES))
    with pytest.raises(PolicyError) as exc_info:
        pol.resolve("read_file", _read("/expenses/q3.csv"))
    assert exc_info.value.reason_code == FORBIDDEN


def test_forbidden_tier_tool_is_denied_or_marked_forbidden(tmp_path):
    """ReasonCode docs: ACTION_FORBIDDEN covers 'unknown tool or forbidden tier'.

    resolve may raise ACTION_FORBIDDEN itself, or return tier=FORBIDDEN for the gateway to
    deny. Either way it must never come back as an allowable tier.
    """
    pol = Policy.load(_write_policy(tmp_path / "pol", _FORBIDDEN_ACTIONS, _MIN_ROLES))
    result = _resolve_or_code(pol, "nuke_everything", {"confirm": "yes"})
    if isinstance(result, ReasonCode):
        assert result == FORBIDDEN
    else:
        assert result.tier == Tier.FORBIDDEN


def test_load_missing_directory_fails_closed(tmp_path):
    with pytest.raises(Exception):  # noqa: B017 - any loud failure is fine; silence is not
        Policy.load(tmp_path / "does-not-exist")


def test_load_uses_safe_yaml_and_never_executes_tags(tmp_path):
    """yaml.load with the full Loader runs !!python tags = code execution from a config file."""
    canary = tmp_path / "pwned"
    evil_actions = f"tools: !!python/object/apply:os.mkdir ['{canary.as_posix()}']\n"
    pol_dir = _write_policy(tmp_path / "pol", evil_actions, _MIN_ROLES)
    with pytest.raises(Exception):  # noqa: B017 - safe_load raises a ConstructorError
        Policy.load(pol_dir)
    assert not canary.exists()


# --------------------------------------------------------------------------------------
# ACCEPT: every tool resolves to the right service / verb / target / tier
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "service", "verb", "target", "tier"),
    [
        ("list_files", {"dir": "/expenses"}, "files", "list", "/expenses", Tier.LOW),
        ("read_file", _read("/expenses/q3.csv"), "files", "read", "/expenses/q3.csv", Tier.LOW),
        (
            "write_file",
            {"path": "/engineering/docs/design.md", "content": "hello"},
            "files",
            "write",
            "/engineering/docs/design.md",
            Tier.MEDIUM,
        ),
        ("send_email", _email("bob@acme.test"), "email", "send", "internal", Tier.MEDIUM),
        ("send_email", _email("x@evil.example"), "email", "send", "external", Tier.HIGH),
        ("wire_transfer", _wire(), "bank", "wire", "*", Tier.HIGH),
        ("query_db", {"table": "vendors"}, "db", "read", "vendors", Tier.LOW),
        ("delete_table", {"table": "payroll"}, "db", "delete", "payroll", Tier.HIGH),
    ],
    ids=["list", "read", "write", "email-int", "email-ext", "wire", "query", "delete"],
)
def test_resolve_maps_tool_to_scope_family_target_and_tier(
    policy, tool, args, service, verb, target, tier
):
    action = policy.resolve(tool, args)
    assert isinstance(action, ResolvedAction)
    assert (action.service, action.verb, action.target) == (service, verb, target)
    assert action.tier == tier


def test_resolve_does_not_depend_on_arg_order(policy):
    a = policy.resolve("send_email", {"body": "b", "subject": "s", "to": "bob@acme.test"})
    assert a.target == "internal"


# --------------------------------------------------------------------------------------
# ACCEPT: "/expenses/q3.csv is allowed by files:read:/expenses/*"
# ACCEPT: "/expenses vs /expenses-evil/x must not match /expenses/*"
# scope_allows(scopes, action) table
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scopes", "tool", "args", "expected"),
    [
        # the Accept bullet
        (["files:read:/expenses/*"], "read_file", _read("/expenses/q3.csv"), True),
        # "*" matches any characters including "/" (roles.yaml grammar)
        (["files:read:/expenses/*"], "read_file", _read("/expenses/2024/q3.csv"), True),
        # prefix confusion: the directory boundary matters
        (["files:read:/expenses/*"], "read_file", _read("/expenses-evil/x"), False),
        (["files:read:/expenses/*"], "read_file", _read("/expenses"), False),
        (["files:read:/expenses/*"], "read_file", _read("/expensesq3.csv"), False),
        (["files:list:/expenses"], "list_files", {"dir": "/expenses"}, True),
        (["files:list:/expenses"], "list_files", {"dir": "/expenses-evil"}, False),
        (["files:list:/expenses"], "list_files", {"dir": "/expenses-evil/x"}, False),
        (["files:list:/expenses"], "list_files", {"dir": "/expenses/sub"}, False),
        # verb must match: a read scope never grants list/write and vice versa
        (["files:read:/expenses/*"], "list_files", {"dir": "/expenses"}, False),
        (["files:list:/expenses"], "read_file", _read("/expenses/q3.csv"), False),
        (
            ["files:read:/expenses/*"],
            "write_file",
            {"path": "/expenses/q3.csv", "content": "x"},
            False,
        ),
        # service must match
        (["db:read:/expenses/*"], "read_file", _read("/expenses/q3.csv"), False),
        # case-sensitive on every OS (fnmatch.fnmatch lowercases on Windows)
        (["files:read:/expenses/*"], "read_file", _read("/Expenses/q3.csv"), False),
        (["files:read:/expenses/*"], "read_file", _read("/EXPENSES/q3.csv"), False),
        (["files:read:/Expenses/*"], "read_file", _read("/expenses/q3.csv"), False),
        (["FILES:READ:/expenses/*"], "read_file", _read("/expenses/q3.csv"), False),
        # wildcards are only meaningful in the target position
        (["files:*:/expenses/*"], "read_file", _read("/expenses/q3.csv"), False),
        (["*:read:/expenses/*"], "read_file", _read("/expenses/q3.csv"), False),
        (["*:*:*"], "read_file", _read("/expenses/q3.csv"), False),
        (["*"], "read_file", _read("/expenses/q3.csv"), False),
        # a scope pattern containing traversal grants nothing (defense in depth behind STS)
        (
            ["files:read:/expenses/../engineering/*"],
            "read_file",
            _read("/engineering/secrets.env"),
            False,
        ),
        # empty / malformed scope lists
        ([], "read_file", _read("/expenses/q3.csv"), False),
        ([""], "read_file", _read("/expenses/q3.csv"), False),
        (["files:read"], "read_file", _read("/expenses/q3.csv"), False),
        # email: target is the recipient class
        (["email:send:internal"], "send_email", _email("bob@acme.test"), True),
        (["email:send:internal"], "send_email", _email("x@evil.example"), False),
        (["email:send:internal"], "send_email", _email("x@acme.test.evil.com"), False),
        (["email:send:external"], "send_email", _email("x@evil.example"), True),
        # bank / db
        (["bank:wire:*"], "wire_transfer", _wire(), True),
        (["email:send:internal"], "wire_transfer", _wire(), False),
        (["db:read:*"], "query_db", {"table": "vendors"}, True),
        (["db:read:vendors"], "query_db", {"table": "vendors"}, True),
        (["db:read:vendors"], "query_db", {"table": "payroll"}, False),
        (["db:read:*"], "delete_table", {"table": "vendors"}, False),
        # one matching scope among several is enough
        (
            ["email:send:internal", "files:list:/expenses", "files:read:/expenses/*"],
            "read_file",
            _read("/expenses/q3.csv"),
            True,
        ),
    ],
)
def test_scope_allows_table(policy, scopes, tool, args, expected):
    action = policy.resolve(tool, args)
    assert policy.scope_allows(scopes, action) is expected


def test_expense_reader_scopes_do_not_reach_secrets(policy):
    """End to end: the real expense_reader scopes vs the attack target of scenario A1."""
    scopes = list(policy.role("expense_reader").allowed_scopes)
    action = policy.resolve("read_file", _read("/engineering/secrets.env"))
    assert policy.scope_allows(scopes, action) is False


# --------------------------------------------------------------------------------------
# ACCEPT: "/expenses/../engineering/secrets.env -> INVALID_ARGUMENTS"
# ACCEPT: "relative paths and backslashes are rejected"
# Attacker edge cases: %2e encoding, backslash, //, trailing /.., NUL, unicode, types
# --------------------------------------------------------------------------------------

TRAVERSAL_PATHS = [
    # the Accept bullet
    "/expenses/../engineering/secrets.env",
    # plain escapes
    "/expenses/../../etc/passwd",
    "/../engineering/secrets.env",
    "/..",
    "/expenses/..",  # trailing /..
    "/expenses/../",
    "/expenses/q3.csv/../../engineering/secrets.env",
    "/expenses/./../engineering/secrets.env",
    "//expenses/../engineering/secrets.env",
    # percent-encoding (decoded later by the resource server's router = traversal)
    "/expenses/%2e%2e/engineering/secrets.env",
    "/expenses/%2E%2E/engineering/secrets.env",
    "/expenses/.%2e/engineering/secrets.env",
    "/expenses/%2e./engineering/secrets.env",
    "/expenses/..%2fengineering%2fsecrets.env",
    "/expenses/%2e%2e%2fengineering%2fsecrets.env",
    "/expenses/%252e%252e/engineering/secrets.env",  # double-encoded
    "/expenses/..%5cengineering%5csecrets.env",  # encoded backslash
    "/expenses/q3.csv%00.env",  # encoded NUL
    # NUL byte
    "/expenses/q3.csv\x00",
    "/expenses/q3.csv\x00/../../engineering/secrets.env",
    # unicode lookalikes that NFKC-normalize to ".." or "/"
    "/expenses/\uff0e\uff0e/engineering/secrets.env",  # FULLWIDTH FULL STOP x2
    "/expenses/\u2025/engineering/secrets.env",  # TWO DOT LEADER
    "/expenses\uff0f..\uff0fengineering\uff0fsecrets.env",  # FULLWIDTH SOLIDUS
    "/expenses/..\uff3cengineering\uff3csecrets.env",  # FULLWIDTH REVERSE SOLIDUS
]

RELATIVE_PATHS = [
    "expenses/q3.csv",
    "./expenses/q3.csv",
    "../engineering/secrets.env",
    "q3.csv",
    ".",
    "..",
    "",
    " /expenses/q3.csv",
    "~/secrets.env",
    "C:/Windows/win.ini",
    "file:///engineering/secrets.env",
    "%2fengineering%2fsecrets.env",
]

BACKSLASH_PATHS = [
    "\\expenses\\q3.csv",
    "/expenses\\q3.csv",
    "/expenses/sub\\q3.csv",
    "/expenses\\..\\engineering\\secrets.env",
    "/expenses/..\\engineering\\secrets.env",
    "\\\\server\\share\\secrets.env",
    "C:\\Windows\\win.ini",
]


@pytest.mark.parametrize("path", TRAVERSAL_PATHS)
def test_read_file_traversal_is_invalid_arguments(policy, path):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("read_file", _read(path))
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize("path", RELATIVE_PATHS)
def test_read_file_relative_path_is_invalid_arguments(policy, path):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("read_file", _read(path))
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize("path", BACKSLASH_PATHS)
def test_read_file_backslash_path_is_invalid_arguments(policy, path):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("read_file", _read(path))
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_files", {"dir": "/expenses/.."}),
        ("list_files", {"dir": "/expenses/../engineering"}),
        ("list_files", {"dir": "expenses"}),
        ("list_files", {"dir": "\\expenses"}),
        ("list_files", {"dir": "/expenses/%2e%2e"}),
        ("write_file", {"path": "/engineering/docs/../../expenses/q3.csv", "content": "x"}),
        ("write_file", {"path": "engineering/docs/x.md", "content": "x"}),
        ("write_file", {"path": "/engineering/docs\\..\\secrets.env", "content": "x"}),
        ("write_file", {"path": "/engineering/docs/x.md\x00", "content": "x"}),
    ],
)
def test_all_path_tools_apply_the_same_path_rules(policy, tool, args):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, args)
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("/expenses//q3.csv", "/expenses/q3.csv"),
        ("/expenses/./q3.csv", "/expenses/q3.csv"),
        ("///expenses/q3.csv", "/expenses/q3.csv"),
        # POSIX normpath KEEPS exactly two leading slashes; matching on "//engineering/..."
        # would dodge the sensitive "files:/engineering/secrets*" pattern.
        ("//engineering/secrets.env", "/engineering/secrets.env"),
        ("//expenses/q3.csv", "/expenses/q3.csv"),
    ],
)
def test_non_canonical_path_is_normalized_or_rejected_never_raw(policy, raw, canonical):
    result = _resolve_or_code(policy, "read_file", _read(raw))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == canonical


def test_double_slash_secrets_path_is_still_sensitive_if_accepted(policy):
    result = _resolve_or_code(policy, "read_file", _read("//engineering/secrets.env"))
    if not isinstance(result, ReasonCode):
        assert result.sensitive is True


def test_list_files_trailing_slash_is_normalized_or_rejected(policy):
    result = _resolve_or_code(policy, "list_files", {"dir": "/expenses/"})
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == "/expenses"
        assert policy.scope_allows(["files:list:/expenses"], result) is True


def test_traversal_that_stays_inside_is_normalized_or_rejected(policy):
    """The authorized target must be the normalized one, never the raw string."""
    result = _resolve_or_code(policy, "read_file", _read("/expenses/sub/../q3.csv"))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == "/expenses/q3.csv"


@pytest.mark.parametrize(
    "bad",
    [None, 123, 1.5, True, b"/expenses/q3.csv", ["/expenses/q3.csv"], {"p": "/expenses"}],
    ids=["none", "int", "float", "bool", "bytes", "list", "dict"],
)
@pytest.mark.parametrize(("tool", "key"), [("read_file", "path"), ("list_files", "dir")])
def test_path_argument_of_wrong_type_is_invalid_arguments(policy, tool, key, bad):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, {key: bad})
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    "path",
    ["/expenses/" + "a" * 100_000, "/expenses/" + "a/" * 5_000 + "q3.csv"],
    ids=["long-name", "deep"],
)
def test_oversized_path_fails_cleanly(policy, path):
    """Either rejected as INVALID_ARGUMENTS or resolved; never an unhandled exception."""
    result = _resolve_or_code(policy, "read_file", _read(path))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target.startswith("/expenses/")


# --------------------------------------------------------------------------------------
# ACCEPT: email bob@acme.test -> internal/medium; x@evil.example -> external/high;
#         x@acme.test.evil.com -> external
# Attacker edge cases: case, trailing dot, subdomain tricks, parser differentials
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("to", "target", "tier"),
    [
        ("bob@acme.test", "internal", Tier.MEDIUM),
        ("x@evil.example", "external", Tier.HIGH),
        ("x@acme.test.evil.com", "external", Tier.HIGH),
    ],
)
def test_email_recipient_class_accept_table(policy, to, target, tier):
    action = policy.resolve("send_email", _email(to))
    assert action.target == target
    assert action.tier == tier


@pytest.mark.parametrize(
    "to",
    [
        "Bob@ACME.TEST",  # domains are case-insensitive (RFC 4343)
        "bob@Acme.Test",
        "alice.smith+expenses@acme.test",
    ],
)
def test_email_internal_variants_are_internal(policy, to):
    action = policy.resolve("send_email", _email(to))
    assert action.target == "internal"
    assert action.tier == Tier.MEDIUM
    assert action.category == "email_internal"


@pytest.mark.parametrize(
    "to",
    [
        "x@evil.example",
        "x@acme.test.evil.com",
        "x@ACME.TEST.evil.com",
        "x@acme.test.evil.com.",  # trailing dot
        "x@evil.example.",  # trailing dot
        "x@evilacme.test",  # suffix match is not a domain match
        "x@notacme.test",
        "x@acme.testevil",
        "x@acme-test.com",
        "x@sub.acme.test",  # exact membership only (see module docstring)
        "x@acme.test@evil.example",  # which @ wins? the real domain is evil.example
        '"bob@acme.test"@evil.example',  # quoted local part containing @
        "x@evil.example,bob@acme.test",  # recipient list: one outsider is enough
        "bob@acme.test,x@evil.example",
        "x@evil.example;bob@acme.test",
        "x@evil.example\r\nbcc:y@acme.test",  # header injection
        "x@evil.example\x00@acme.test",  # NUL truncation
        "x@evil.example%acme.test",  # legacy % routing
        "x@\u0430cme.test",  # Cyrillic 'a' homoglyph
        "x@acme.te\u017ft",  # LATIN SMALL LONG S: casefold() turns it into 's'
        "x@xn--acme-test.example",
        "x@[127.0.0.1]",
    ],
)
def test_email_never_classified_internal_for_outside_or_ambiguous_domains(policy, to):
    """Misclassifying as internal downgrades HIGH (human approval) to MEDIUM: an exfil path."""
    result = _resolve_or_code(policy, "send_email", _email(to))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == "external"
        assert result.tier == Tier.HIGH
        assert result.category == "email_external"


def test_email_trailing_dot_internal_domain_fails_cleanly(policy):
    """'acme.test.' is the same DNS name; either class is defensible, a crash is not."""
    result = _resolve_or_code(policy, "send_email", _email("bob@acme.test."))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target in {"internal", "external"}


@pytest.mark.parametrize(
    "to",
    ["", "bob", "bob@", "acme.test", None, 42, ["bob@acme.test"], {"addr": "bob@acme.test"}],
    ids=["empty", "no-at", "no-domain", "domain-only", "none", "int", "list", "dict"],
)
def test_email_unparseable_or_wrong_type_recipient_is_invalid_arguments(policy, to):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("send_email", _email(to))
    assert exc_info.value.reason_code == INVALID


# --------------------------------------------------------------------------------------
# ACCEPT: "an unknown tool -> ACTION_FORBIDDEN"
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [
        "delete_everything",
        "",
        "READ_FILE",  # tool names are exact
        "read_file ",
        " read_file",
        "read-file",
        "read_file\x00",
        "__class__",  # attribute-lookup confusion
        "__init__",
        "tools",  # top-level YAML keys are not tools
        "categories",
        "internal_email_domains",
        "sensitive",
        "../read_file",
    ],
)
def test_unknown_tool_is_action_forbidden(policy, tool):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, {"path": "/expenses/q3.csv"})
    assert exc_info.value.reason_code == FORBIDDEN


def test_unknown_tool_is_checked_before_arguments(policy):
    """Pipeline step 5: resolve the tool (ACTION_FORBIDDEN) before validating args."""
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("exfiltrate", {"path": "/expenses/../engineering/secrets.env"})
    assert exc_info.value.reason_code == FORBIDDEN


# --------------------------------------------------------------------------------------
# ACCEPT: "missing or extra args -> INVALID_ARGUMENTS"
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        # missing
        ("read_file", {}),
        ("list_files", {}),
        ("write_file", {"path": "/engineering/docs/x.md"}),
        ("send_email", {"to": "bob@acme.test", "subject": "s"}),
        ("wire_transfer", {"to_account": "A", "amount": 1}),
        ("query_db", {}),
        ("delete_table", {}),
        # extra
        ("read_file", {"path": "/expenses/q3.csv", "extra": 1}),
        ("read_file", {"path": "/expenses/q3.csv", "task_id": "t-other"}),  # smuggled
        ("list_files", {"dir": "/expenses", "path": "/engineering"}),
        ("send_email", {**_email("bob@acme.test"), "bcc": "x@evil.example"}),
        ("send_email", {**_email("bob@acme.test"), "cc": "x@evil.example"}),
        ("wire_transfer", {**_wire(), "from_account": "CEO"}),
        ("query_db", {"table": "vendors", "where": "1=1"}),
        # wrong key names / case
        ("read_file", {"Path": "/expenses/q3.csv"}),
        ("read_file", {"dir": "/expenses/q3.csv"}),
        ("send_email", {"To": "bob@acme.test", "subject": "s", "body": "b"}),
        # args itself is not a mapping
        ("read_file", None),
        ("read_file", ["/expenses/q3.csv"]),
        ("read_file", "/expenses/q3.csv"),
    ],
)
def test_missing_extra_or_malformed_args_are_invalid_arguments(policy, tool, args):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, args)
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    "table",
    [
        "",
        "../admin/reset",  # becomes the resource URL path /db/{table}
        "vendors/../payroll",
        "a/b",
        "..",
        "vendors\\x",
        "vendors; DROP TABLE payroll",
        "vendors'--",
        "vendors\x00",
        "%2e%2e",
        None,
        7,
        ["vendors"],
    ],
)
@pytest.mark.parametrize("tool", ["query_db", "delete_table"])
def test_db_table_must_be_a_simple_identifier(policy, tool, table):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, {"table": table})
    assert exc_info.value.reason_code == INVALID


# --------------------------------------------------------------------------------------
# ACCEPT: role_permits table
#   "requesting files:read:/engineering/* as expense_reader -> not permitted"
#   "a requested scope that is a subset of an allowed one (files:read:/expenses/q3.csv)
#    -> permitted"
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "requested", "expected"),
    [
        # the Accept bullets
        ("expense_reader", ["files:read:/engineering/*"], False),
        ("expense_reader", ["files:read:/expenses/q3.csv"], True),
        # exact and full-role requests
        ("expense_reader", ["files:read:/expenses/*"], True),
        ("expense_reader", ["files:list:/expenses"], True),
        ("expense_reader", ["email:send:internal"], True),
        (
            "expense_reader",
            ["files:list:/expenses", "files:read:/expenses/*", "email:send:internal"],
            True,
        ),
        ("expense_reader", ["files:read:/expenses/2024/q3.csv"], True),
        # EVERY requested scope must be covered
        ("expense_reader", ["files:read:/expenses/*", "files:read:/engineering/*"], False),
        ("expense_reader", ["email:send:internal", "email:send:external"], False),
        # traversal hidden inside a requested pattern: string-matches "/expenses/*" but
        # as a pattern would reach /engineering
        ("expense_reader", ["files:read:/expenses/../engineering/*"], False),
        ("expense_reader", ["files:read:/expenses/*/../../engineering/*"], False),
        ("expense_reader", ["files:read:/expenses/../engineering/secrets.env"], False),
        ("expense_reader", ["files:read:/expenses/%2e%2e/engineering/*"], False),
        ("expense_reader", ["files:read:/expenses/\uff0e\uff0e/engineering/*"], False),
        ("expense_reader", ["files:read:/expenses\\..\\engineering\\*"], False),
        ("expense_reader", ["files:read:/expenses/q3.csv\x00"], False),
        # broadening tricks
        ("expense_reader", ["files:read:/expenses-evil/*"], False),
        ("expense_reader", ["files:read:/expenses*"], False),
        ("expense_reader", ["files:read:/*"], False),
        ("expense_reader", ["files:read:*"], False),
        ("expense_reader", ["files:*:/expenses/*"], False),
        ("expense_reader", ["*:*:*"], False),
        ("expense_reader", ["*"], False),
        ("expense_reader", ["files:list:/expenses-evil"], False),
        ("expense_reader", ["files:list:/expenses/sub"], False),
        ("expense_reader", ["files:list:/"], False),
        # verb / service escalation
        ("expense_reader", ["files:write:/expenses/q3.csv"], False),
        ("expense_reader", ["email:send:external"], False),
        ("expense_reader", ["email:send:*"], False),
        ("expense_reader", ["bank:wire:*"], False),
        ("expense_reader", ["db:read:*"], False),
        ("expense_reader", ["db:read:vendors"], False),
        # malformed scope strings
        ("expense_reader", [""], False),
        ("expense_reader", ["files:read"], False),
        ("expense_reader", ["files:read:"], False),
        ("expense_reader", ["files::/expenses/*"], False),
        ("expense_reader", ["FILES:READ:/expenses/*"], False),
        ("expense_reader", ["files:read:expenses/q3.csv"], False),
        # eng_assistant
        ("eng_assistant", ["files:write:/engineering/docs/new.md"], True),
        ("eng_assistant", ["files:read:/engineering/secrets.env"], True),
        ("eng_assistant", ["files:write:/engineering/secrets.env"], False),
        ("eng_assistant", ["files:write:/engineering/docs/../secrets.env"], False),
        ("eng_assistant", ["files:read:/expenses/*"], False),
        ("eng_assistant", ["email:send:external"], False),
        # finance_ops
        ("finance_ops", ["bank:wire:*", "db:read:payroll", "email:send:external"], True),
        ("finance_ops", ["db:read:*"], True),
        ("finance_ops", ["db:delete:payroll"], False),
        ("finance_ops", ["files:read:/engineering/*"], False),
    ],
)
def test_role_permits_table(policy, role, requested, expected):
    assert _permits(policy, role, requested) is expected


@pytest.mark.parametrize("role", ["admin", "", "EXPENSE_READER", "expense_reader ", "__class__"])
def test_role_permits_unknown_role_is_not_permitted(policy, role):
    assert _permits(policy, role, ["files:read:/expenses/q3.csv"]) is False


@pytest.mark.parametrize(
    "role", ["expense_reader", "eng_assistant", "finance_ops"], ids=lambda r: r
)
def test_every_role_permits_its_own_allowed_scopes(policy, role):
    assert _permits(policy, role, list(policy.role(role).allowed_scopes)) is True


# --------------------------------------------------------------------------------------
# role(name)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "scopes", "profile", "rate"),
    [
        (
            "expense_reader",
            ["files:list:/expenses", "files:read:/expenses/*", "email:send:internal"],
            {"expenses", "email_internal"},
            30,
        ),
        (
            "eng_assistant",
            [
                "files:list:/engineering",
                "files:read:/engineering/*",
                "files:write:/engineering/docs/*",
                "email:send:internal",
            ],
            {"engineering", "email_internal"},
            60,
        ),
        (
            "finance_ops",
            [
                "files:list:/expenses",
                "files:read:/expenses/*",
                "db:read:*",
                "bank:wire:*",
                "email:send:internal",
                "email:send:external",
            ],
            {"expenses", "finance", "email_internal", "email_external"},
            20,
        ),
    ],
)
def test_role_returns_policy_values(policy, name, scopes, profile, rate):
    r = policy.role(name)
    assert list(r.allowed_scopes) == scopes
    assert set(r.profile) == profile
    assert r.rate_limit_per_minute == rate


@pytest.mark.parametrize("name", ["admin", "", "Expense_Reader", "__class__", "roles"])
def test_role_unknown_name_raises(policy, name):
    """Registry (T2.1) maps this to 422; returning a default role would be fail-open."""
    with pytest.raises((PolicyError, LookupError)):
        policy.role(name)


# --------------------------------------------------------------------------------------
# ACCEPT: "categories and sensitive are computed correctly"
# categories are matched against "<service>:<target>" (actions.yaml)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "category"),
    [
        ("list_files", {"dir": "/expenses"}, "expenses"),
        ("read_file", _read("/expenses/q3.csv"), "expenses"),
        ("read_file", _read("/expenses/2024/q3.csv"), "expenses"),
        ("list_files", {"dir": "/engineering"}, "engineering"),
        ("read_file", _read("/engineering/docs/design.md"), "engineering"),
        ("read_file", _read("/engineering/secrets.env"), "engineering"),
        (
            "write_file",
            {"path": "/engineering/docs/design.md", "content": "x"},
            "engineering",
        ),
        ("wire_transfer", _wire(), "finance"),
        ("query_db", {"table": "vendors"}, "finance"),
        ("delete_table", {"table": "payroll"}, "finance"),
        ("send_email", _email("bob@acme.test"), "email_internal"),
        ("send_email", _email("x@evil.example"), "email_external"),
        # uncategorized: out of every profile (monitor's out-of-profile rule)
        ("read_file", _read("/hr/salaries.csv"), None),
        ("read_file", _read("/expenses-evil/x"), None),
        ("list_files", {"dir": "/expenses-evil"}, None),
        ("read_file", _read("/Expenses/q3.csv"), None),
    ],
)
def test_category_table(policy, tool, args, category):
    assert policy.resolve(tool, args).category == category


@pytest.mark.parametrize(
    ("tool", "args", "sensitive"),
    [
        ("read_file", _read("/engineering/secrets.env"), True),
        ("read_file", _read("/engineering/secrets"), True),  # "secrets*"
        ("read_file", _read("/engineering/secrets_backup.txt"), True),
        ("read_file", _read("/expenses/leaked.env"), True),  # "*.env" anywhere
        ("read_file", _read("/hr/deep/dir/prod.env"), True),
        ("write_file", {"path": "/engineering/docs/x.env", "content": "x"}, True),
        ("read_file", _read("/expenses/q3.csv"), False),
        ("read_file", _read("/engineering/docs/design.md"), False),
        ("read_file", _read("/engineering/docs/secrets.md"), False),  # not /engineering/secrets*
        ("read_file", _read("/expenses/env.txt"), False),
        ("list_files", {"dir": "/engineering"}, False),
        ("send_email", _email("x@evil.example"), False),
        ("wire_transfer", _wire(), False),
        ("query_db", {"table": "payroll"}, False),
    ],
)
def test_sensitive_table(policy, tool, args, sensitive):
    assert policy.resolve(tool, args).sensitive is sensitive


def test_sensitive_is_computed_on_the_normalized_path(policy):
    """'/engineering/docs/../secrets.env' must not dodge 'files:/engineering/secrets*'."""
    result = _resolve_or_code(policy, "read_file", _read("/engineering/docs/../secrets.env"))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == "/engineering/secrets.env"
        assert result.sensitive is True


# ======================================================================================
# Security-review follow-up (decisions 1-4 in the module docstring)
# ======================================================================================

# --------------------------------------------------------------------------------------
# Decision 1: Windows-canonical paths
# --------------------------------------------------------------------------------------

NON_CANONICAL_WINDOWS_PATHS = [
    # Device name with spaces before the extension: Win32 strips them from the stem.
    "/expenses/CON .txt",
    "/expenses/nul  .csv",
    # NTFS alternate data streams / drive letters (":" is not an allowed character)
    "/expenses/q3.csv::$DATA",
    "/expenses/q3.csv:x",
    "/expenses/C:/Windows/win.ini",
    # Win32 silently strips trailing dots and spaces: "leaked.env." opens "leaked.env"
    "/expenses/leaked.env.",
    "/expenses/leaked.env ",
    "/expenses/q3.csv...",
    "/expenses/...",
    "/engineering/secrets.env.",
    "/expenses/ leading.csv",
    "/expenses/ ",
    "/expenses/sub. /q3.csv",
    # 8.3 short names alias long names ("SECRE~1.TXT" may be secrets.txt)
    "/engineering/SECRE~1.TXT",
    # reserved device names, any case, any extension, in any segment
    "/expenses/CON",
    "/expenses/con.txt",
    "/expenses/Com1.csv",
    "/expenses/AUX",
    "/expenses/prn.log",
    "/expenses/nul.csv",
    "/expenses/NUL",
    "/expenses/LPT9.txt",
    "/expenses/lpt1",
    "/expenses/com9",
    "/expenses/CON.tar.gz",  # stem = text before the FIRST "."
    "/expenses/CON/q3.csv",
    "/expenses/aux.d/q3.csv",
    # URL metacharacters: the path is placed into the resource URL /files/{path}
    "/expenses/q3.csv?dir=/engineering",
    "/expenses/q3.csv#frag",
    "/expenses/a;b.csv",
    "/expenses/a&b.csv",
    "/expenses/a+b.csv",
    # characters Windows forbids or treats specially
    "/expenses/a<b",
    "/expenses/a>b",
    "/expenses/a|b",
    '/expenses/a"b',
    "/expenses/a*b.csv",
    "/expenses/*",
    "/expenses/q?.csv",
    "/expenses/a'b.csv",
    "/expenses/a$b.csv",
    # control characters and non-ASCII (outside [A-Za-z0-9._ -])
    "/expenses/q3.csv\t",
    "/expenses/a\nb.csv",
    "/expenses/r\u00e9sum\u00e9.csv",
    "/expenses/COM\u00b9.csv",  # superscript 1: Windows treats it as the COM1 device
    "/expenses/q3\u200b.csv",  # zero-width space
]


@pytest.mark.parametrize("path", NON_CANONICAL_WINDOWS_PATHS)
def test_non_windows_canonical_path_is_invalid_arguments(policy, path):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve("read_file", _read(path))
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_files", {"dir": "/expenses/CON"}),
        ("list_files", {"dir": "/expenses "}),
        ("list_files", {"dir": "/expenses."}),
        ("list_files", {"dir": "/expenses?x=1"}),
        ("write_file", {"path": "/engineering/docs/CON", "content": "x"}),
        ("write_file", {"path": "/engineering/docs/x.md:stream", "content": "x"}),
        ("write_file", {"path": "/engineering/docs/x.md.", "content": "x"}),
        ("write_file", {"path": "/engineering/docs/DESIGN~1.MD", "content": "x"}),
    ],
)
def test_windows_canonical_rules_apply_to_every_path_tool(policy, tool, args):
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, args)
    assert exc_info.value.reason_code == INVALID


@pytest.mark.parametrize(
    "path",
    [
        "/expenses/q3 report.csv",  # inner space is fine
        "/expenses/q4_draft.csv",
        "/expenses/vendor_note.txt",
        "/expenses/2024-Q3.v2.csv",
        "/expenses/conf.txt",  # stem "conf" is not a device name
        "/expenses/console.csv",
        "/expenses/COM10.csv",  # only COM1-COM9 are reserved
        "/expenses/LPT0.csv",
        "/expenses/auxiliary.csv",
    ],
)
def test_windows_canonical_legal_paths_still_resolve_and_are_allowed(policy, path):
    action = policy.resolve("read_file", _read(path))
    assert action.target == path
    assert policy.scope_allows(["files:read:/expenses/*"], action) is True


# --------------------------------------------------------------------------------------
# Decision 2: sensitive is case-insensitive; scopes and categories stay case-sensitive
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/engineering/SECRETS.ENV",
        "/engineering/Secrets.env",
        "/engineering/secrets.ENV",
        "/ENGINEERING/secrets.env",
        "/Engineering/Secrets",
        "/expenses/leaked.ENV",
        "/expenses/Leaked.Env",
    ],
)
def test_sensitive_match_is_case_insensitive(policy, path):
    assert policy.resolve("read_file", _read(path)).sensitive is True


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("/Expenses/q3.csv", "files:read:/expenses/*"),
        ("/EXPENSES/q3.csv", "files:read:/expenses/*"),
        ("/ENGINEERING/secrets.env", "files:read:/engineering/*"),
        ("/expenses/q3.csv", "files:read:/Expenses/*"),
    ],
)
def test_scope_match_stays_case_sensitive(policy, path, scope):
    action = policy.resolve("read_file", _read(path))
    assert policy.scope_allows([scope], action) is False


@pytest.mark.parametrize(
    "path", ["/Expenses/q3.csv", "/ENGINEERING/secrets.env", "/Engineering/docs/design.md"]
)
def test_category_match_stays_case_sensitive(policy, path):
    assert policy.resolve("read_file", _read(path)).category is None


def test_case_variant_secret_is_sensitive_but_uncategorized_and_unscoped(policy):
    """Odd casing must not grant access, yet must still arm the exfil rule."""
    action = policy.resolve("read_file", _read("/ENGINEERING/SECRETS.ENV"))
    assert action.sensitive is True
    assert action.category is None
    assert policy.scope_allows(["files:read:/engineering/*"], action) is False


# --------------------------------------------------------------------------------------
# Decision 3: scope pattern limits (<= 4 "*", target <= 256 chars)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "requested",
    [
        "files:read:/expenses/*a*a*a*a*a",  # 5 stars
        "files:read:/expenses/*****",
        "files:read:/expenses/*/*/*/*/*",
        "files:read:/expenses/" + "a" * 247,  # target = 257 chars
        "files:read:/expenses/" + "a" * 5_000,
    ],
    ids=["5-stars-interleaved", "5-stars-run", "5-stars-segments", "257-chars", "huge"],
)
def test_role_permits_rejects_scope_over_pattern_limits(policy, requested):
    assert _permits(policy, "expense_reader", [requested]) is False


@pytest.mark.parametrize(
    "requested",
    [
        "files:read:/expenses/*a*b*c*",  # exactly 4 stars
        "files:read:/expenses/" + "a" * 246,  # target = exactly 256 chars
    ],
    ids=["4-stars", "256-chars"],
)
def test_role_permits_accepts_scope_at_pattern_limits(policy, requested):
    target = requested.split(":", 2)[2]
    assert target.count("*") <= 4 and len(target) <= 256
    assert _permits(policy, "expense_reader", [requested]) is True


def test_scope_allows_ignores_scope_over_star_limit(policy):
    """A 5-star scope that would glob-match must grant nothing (it should never be issued)."""
    action = policy.resolve("read_file", _read("/expenses/aaaaaa"))
    assert policy.scope_allows(["files:read:/expenses/*a*a*a*a*a"], action) is False


def test_scope_allows_long_legal_input_completes(policy):
    """Worst case for naive backtracking: 4 stars, long target, no match at the end."""
    path = "/expenses/" + "a" * 200 + ".csv"
    action = policy.resolve("read_file", _read(path))
    scope = "files:read:/expenses/*a*a*a*a" + "a" * 200
    assert len(scope.split(":", 2)[2]) <= 256
    assert policy.scope_allows([scope], action) is False
    assert policy.scope_allows(["files:read:/expenses/*a*a*a*.csv"], action) is True


# --------------------------------------------------------------------------------------
# Decision 4: policy loading fails closed with PolicyConfigError
# Each case copies the REAL policy into tmp_path and makes exactly one edit.
# --------------------------------------------------------------------------------------


def _copy_real_policy(tmp_path: Path) -> Path:
    dst = tmp_path / "policy"
    dst.mkdir()
    for name in ("roles.yaml", "actions.yaml"):
        shutil.copyfile(POLICY_DIR / name, dst / name)
    return dst


def _edit(dir_: Path, name: str, old: str, new: str) -> None:
    """Replace the first occurrence of `old`; fail loudly if the real file changed shape."""
    path = dir_ / name
    text = path.read_text(encoding="utf-8")
    assert old in text, f"test fixture out of date: {old!r} not found in {name}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_unedited_copy_of_real_policy_loads(tmp_path):
    """Control: proves each failure below is caused by its single edit."""
    pol = Policy.load(_copy_real_policy(tmp_path))
    assert pol.resolve("read_file", _read("/expenses/q3.csv")).target == "/expenses/q3.csv"


_DUP_ROLE = """
  expense_reader:
    description: duplicate that silently widens the role
    allowed_scopes: ["files:read:/*"]
    profile: [expenses]
    rate_limit_per_minute: 30
"""

_DUP_TOOL = """  read_file:
    service: files
    verb: read
    target_arg: path
    tier: low
    args: [path, extra]

"""

_CONFIG_EDITS = [
    # duplicate keys: PyYAML silently keeps the LAST one
    pytest.param(
        "roles.yaml",
        "rate_limit_per_minute: 20\n",
        "rate_limit_per_minute: 20\n" + _DUP_ROLE,
        id="dup-role",
    ),
    pytest.param(
        "roles.yaml",
        '    allowed_scopes:\n      - "files:list:/expenses"',
        '    allowed_scopes: ["files:read:/*"]\n'
        '    allowed_scopes:\n      - "files:list:/expenses"',
        id="dup-allowed_scopes",
    ),
    pytest.param("actions.yaml", "  write_file:\n", _DUP_TOOL + "  write_file:\n", id="dup-tool"),
    pytest.param(
        "actions.yaml",
        "categories:\n",
        'internal_email_domains: ["evil.example"]\n\ncategories:\n',
        id="dup-internal_email_domains",
    ),
    # unknown service prefix in sensitive / categories
    pytest.param(
        "actions.yaml",
        '"files:/engineering/secrets*"',
        '"file:/engineering/secrets*"',
        id="sensitive-unknown-service",
    ),
    pytest.param(
        "actions.yaml",
        '"files:/engineering/*"]',
        '"file:/engineering/*"]',
        id="category-unknown-service",
    ),
    # unknown tier
    pytest.param("actions.yaml", "    tier: low\n", "    tier: lowest\n", id="unknown-tier"),
    pytest.param(
        "actions.yaml",
        "      external: high\n",
        "      external: hihg\n",
        id="unknown-tiers-value",
    ),
    # unknown key on a tool
    pytest.param(
        "actions.yaml",
        "    target_arg: path\n    tier: low\n",
        "    target_arg: path\n    tier: low\n    skip_scope_check: true\n",
        id="unknown-tool-key",
    ),
    # tool without args
    pytest.param("actions.yaml", "    args: [path]\n", "", id="missing-args"),
]


@pytest.mark.parametrize(("name", "old", "new"), _CONFIG_EDITS)
def test_bad_policy_config_fails_closed(tmp_path, name, old, new):
    pol_dir = _copy_real_policy(tmp_path)
    _edit(pol_dir, name, old, new)
    with pytest.raises(policy_mod.PolicyConfigError):
        Policy.load(pol_dir)
