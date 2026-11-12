"""T1.4 Policy engine tests (docs/ROADMAP.md, docs/CONTRACTS.md, policy/*.yaml).

The policy engine turns a tool call into a ``ResolvedAction`` and decides whether scope strings
cover it. Most tests are negative tests pinning the exact ``ReasonCode`` for hostile input.

Spec notes: scope and category matching is case-SENSITIVE (only ``*`` is a wildcard); ``sensitive``
is case-INSENSITIVE; email domains are exact (case-insensitive) membership; paths are normalized
and must be Windows-canonical (segments only ``[A-Za-z0-9._ -]``, no trailing dot/space, no
reserved device names), percent-encoded/NFKC/backslash/NUL paths are INVALID_ARGUMENTS; scope
targets over 4 ``*`` or 256 chars grant nothing; loading fails closed with ``PolicyConfigError``.
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
    """The ResolvedAction, or the ReasonCode of the PolicyError (other exceptions fail the test)."""
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


def _assert_code(policy: Policy, tool: str, args, code: ReasonCode = INVALID) -> None:
    with pytest.raises(PolicyError) as exc_info:
        policy.resolve(tool, args)
    assert exc_info.value.reason_code == code


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


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


def test_load_uses_the_given_directory_and_forbidden_tier_is_never_allowable(tmp_path):
    pol = Policy.load(_write_policy(tmp_path / "pol", _FORBIDDEN_ACTIONS, _MIN_ROLES))
    _assert_code(pol, "read_file", _read("/expenses/q3.csv"), FORBIDDEN)  # real tools unknown
    result = _resolve_or_code(pol, "nuke_everything", {"confirm": "yes"})
    if isinstance(result, ReasonCode):
        assert result == FORBIDDEN
    else:
        assert result.tier == Tier.FORBIDDEN


def test_load_missing_directory_fails_closed(tmp_path):
    with pytest.raises(Exception):  # noqa: B017 - any loud failure is fine; silence is not
        Policy.load(tmp_path / "does-not-exist")


def test_load_uses_safe_yaml_and_never_executes_tags(tmp_path):
    canary = tmp_path / "pwned"
    evil_actions = f"tools: !!python/object/apply:os.mkdir ['{canary.as_posix()}']\n"
    pol_dir = _write_policy(tmp_path / "pol", evil_actions, _MIN_ROLES)
    with pytest.raises(Exception):  # noqa: B017 - safe_load raises a ConstructorError
        Policy.load(pol_dir)
    assert not canary.exists()


# --------------------------------------------------------------------------------------
# resolve: every tool maps to the right service / verb / target / tier
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "service", "verb", "target", "tier"),
    [
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
        ("query_db", {"table": "vendors"}, "db", "read", "vendors", Tier.LOW),
    ],
)
def test_resolve_maps_tool_to_scope_family_target_and_tier(
    policy, tool, args, service, verb, target, tier
):
    action = policy.resolve(tool, args)
    assert isinstance(action, ResolvedAction)
    assert (action.service, action.verb, action.target) == (service, verb, target)
    assert action.tier == tier


@pytest.mark.parametrize(
    "tool",
    ["delete_everything", "READ_FILE"],
)
def test_unknown_tool_is_action_forbidden(policy, tool):
    _assert_code(policy, tool, {"path": "/expenses/q3.csv"}, FORBIDDEN)


def test_unknown_tool_is_checked_before_arguments(policy):
    _assert_code(policy, "exfiltrate", {"path": "/expenses/../engineering/secrets.env"}, FORBIDDEN)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("read_file", {}),  # missing
        ("read_file", {"path": "/expenses/q3.csv", "task_id": "t-other"}),  # smuggled extra
        ("send_email", {**_email("bob@acme.test"), "bcc": "x@evil.example"}),
        ("read_file", None),  # args is not a mapping
    ],
)
def test_missing_extra_or_malformed_args_are_invalid_arguments(policy, tool, args):
    _assert_code(policy, tool, args)


@pytest.mark.parametrize("tool", ["query_db", "delete_table"])
@pytest.mark.parametrize("table", ["", "../admin/reset", "users; DROP TABLE x", None])
def test_db_table_must_be_a_simple_identifier(policy, tool, table):
    _assert_code(policy, tool, {"table": table})


# --------------------------------------------------------------------------------------
# Paths: traversal, relative, backslash, encoding, Windows canonical form
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/expenses/../engineering/secrets.env",  # the classic
        "/expenses/%2e%2e/engineering/secrets.env",  # percent-encoded (decoded downstream)
        "/expenses/q3.csv\x00",  # NUL byte
        "/expenses/\uff0e\uff0e/engineering/secrets.env",  # NFKC fullwidth ".."
    ],
)
def test_read_file_traversal_or_encoded_escape_is_invalid_arguments(policy, path):
    _assert_code(policy, "read_file", _read(path))


@pytest.mark.parametrize(
    "path",
    [
        "expenses/q3.csv",
        "",
    ],
)
def test_read_file_relative_path_is_invalid_arguments(policy, path):
    _assert_code(policy, "read_file", _read(path))


@pytest.mark.parametrize(
    "path",
    ["\\expenses\\q3.csv", "C:\\Windows\\win.ini"],
)
def test_read_file_backslash_path_is_invalid_arguments(policy, path):
    _assert_code(policy, "read_file", _read(path))


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_files", {"dir": "/expenses/CON"}),  # Windows rules apply to every path tool
        ("write_file", {"path": "/engineering/docs/x.md.", "content": "x"}),
    ],
)
def test_all_path_tools_apply_the_same_path_rules(policy, tool, args):
    _assert_code(policy, tool, args)


@pytest.mark.parametrize("bad", [None, 123])
@pytest.mark.parametrize(("tool", "key"), [("read_file", "path")])
def test_path_argument_of_wrong_type_is_invalid_arguments(policy, tool, key, bad):
    _assert_code(policy, tool, {key: bad})


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("/expenses//q3.csv", "/expenses/q3.csv"),
        ("/expenses/sub/../q3.csv", "/expenses/q3.csv"),
        # POSIX normpath KEEPS two leading slashes; matching on "//engineering/..." would dodge
        # the sensitive "files:/engineering/secrets*" pattern.
        ("//engineering/secrets.env", "/engineering/secrets.env"),
    ],
)
def test_non_canonical_path_is_normalized_or_rejected_never_raw(policy, raw, canonical):
    result = _resolve_or_code(policy, "read_file", _read(raw))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert result.target == canonical
        assert result.sensitive is (canonical == "/engineering/secrets.env")


@pytest.mark.parametrize(
    "path",
    [
        "/expenses/q3.csv::$DATA",  # NTFS alternate data stream
        "/expenses/leaked.env.",  # Win32 strips trailing dots: opens "leaked.env"
        "/expenses/CON",  # reserved device names
        "/expenses/COM\u00b9.csv",  # superscript 1: Windows treats it as COM1
    ],
)
def test_non_windows_canonical_path_is_invalid_arguments(policy, path):
    _assert_code(policy, "read_file", _read(path))


@pytest.mark.parametrize(
    "path",
    [
        "/expenses/q3 report.csv",  # inner space is fine
        "/expenses/conf.txt",  # stem "conf" is not a device name
    ],
)
def test_windows_canonical_legal_paths_still_resolve_and_are_allowed(policy, path):
    action = policy.resolve("read_file", _read(path))
    assert action.target == path
    assert policy.scope_allows(["files:read:/expenses/*"], action) is True


# --------------------------------------------------------------------------------------
# scope_allows
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scopes", "tool", "args", "expected"),
    [
        (["files:read:/expenses/*"], "read_file", _read("/expenses/q3.csv"), True),
        (
            ["files:read:/expenses/*"],
            "read_file",
            _read("/expenses/2024/q3.csv"),
            True,
        ),  # * spans /
        # prefix confusion: the directory boundary matters
        (["files:read:/expenses/*"], "read_file", _read("/expenses-evil/x"), False),
        (["files:list:/expenses"], "list_files", {"dir": "/expenses"}, True),
        # verb and service must match
        # case-sensitive on every OS
        (["files:read:/expenses/*"], "read_file", _read("/Expenses/q3.csv"), False),
        # wildcards only in the target position
        # a scope pattern containing traversal grants nothing
        (["files:read:/expenses/../engineering/*"], "read_file", _read("/engineering/a"), False),
        # empty / malformed scope lists
        # email target is the recipient class
        (["email:send:internal"], "send_email", _email("bob@acme.test"), True),
        (["email:send:internal"], "send_email", _email("x@evil.example"), False),
        (["email:send:internal"], "send_email", _email("x@acme.test.evil.com"), False),
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
    """Scenario A1: real expense_reader scopes vs the attack target."""
    scopes = list(policy.role("expense_reader").allowed_scopes)
    action = policy.resolve("read_file", _read("/engineering/secrets.env"))
    assert policy.scope_allows(scopes, action) is False


def test_scope_allows_ignores_scope_over_star_limit(policy):
    action = policy.resolve("read_file", _read("/expenses/aaaaaa"))
    assert policy.scope_allows(["files:read:/expenses/*a*a*a*a*a"], action) is False


# --------------------------------------------------------------------------------------
# Email recipient classification
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("to", ["bob@acme.test", "Bob@ACME.TEST"])
def test_email_internal_variants_are_internal(policy, to):
    action = policy.resolve("send_email", _email(to))
    assert (action.target, action.tier, action.category) == (
        "internal",
        Tier.MEDIUM,
        "email_internal",
    )


@pytest.mark.parametrize(
    "to",
    [
        "x@evil.example",
        "x@acme.test.evil.com",
        "x@sub.acme.test",  # exact membership only
        "x@\u0430cme.test",  # Cyrillic 'a' homoglyph
    ],
)
def test_email_never_classified_internal_for_outside_or_ambiguous_domains(policy, to):
    """Misclassifying as internal downgrades HIGH (human approval) to MEDIUM: an exfil path."""
    result = _resolve_or_code(policy, "send_email", _email(to))
    if isinstance(result, ReasonCode):
        assert result == INVALID
    else:
        assert (result.target, result.tier, result.category) == (
            "external",
            Tier.HIGH,
            "email_external",
        )


@pytest.mark.parametrize("to", ["", "bob", None])
def test_email_unparseable_or_wrong_type_recipient_is_invalid_arguments(policy, to):
    _assert_code(policy, "send_email", _email(to))


# --------------------------------------------------------------------------------------
# role_permits / role
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "requested", "expected"),
    [
        ("expense_reader", ["files:read:/engineering/*"], False),
        ("expense_reader", ["files:read:/expenses/q3.csv"], True),  # subset of an allowed scope
        # EVERY requested scope must be covered
        ("expense_reader", ["files:read:/expenses/*", "files:read:/engineering/*"], False),
        # traversal / encoding hidden inside a requested pattern
        ("expense_reader", ["files:read:/expenses/../engineering/*"], False),
        # broadening tricks
        # verb / service escalation
        # malformed scope strings
        ("finance_ops", ["bank:wire:*", "db:read:payroll", "email:send:external"], True),
        # scope pattern limits: > 4 stars or > 256 chars grant nothing; the limit itself is fine
        ("expense_reader", ["files:read:/expenses/*a*a*a*a*a"], False),
        ("expense_reader", ["files:read:/expenses/*a*b*c*"], True),
    ],
)
def test_role_permits_table(policy, role, requested, expected):
    assert _permits(policy, role, requested) is expected


@pytest.mark.parametrize("role", ["admin", "EXPENSE_READER"])
def test_role_permits_unknown_role_is_not_permitted(policy, role):
    assert _permits(policy, role, ["files:read:/expenses/q3.csv"]) is False


@pytest.mark.parametrize("name", ["admin", "Expense_Reader"])
def test_role_unknown_name_raises(policy, name):
    """Returning a default role would be fail-open."""
    with pytest.raises((PolicyError, LookupError)):
        policy.role(name)


# --------------------------------------------------------------------------------------
# Categories and sensitive
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "category"),
    [
        ("read_file", _read("/expenses/2024/q3.csv"), "expenses"),
        ("read_file", _read("/engineering/secrets.env"), "engineering"),
        ("wire_transfer", _wire(), "finance"),
        # uncategorized: out of every profile (monitor's out-of-profile rule)
        ("read_file", _read("/Expenses/q3.csv"), None),  # categories are case-sensitive
    ],
)
def test_category_table(policy, tool, args, category):
    assert policy.resolve(tool, args).category == category


@pytest.mark.parametrize(
    ("tool", "args", "sensitive"),
    [
        ("read_file", _read("/engineering/secrets.env"), True),
        ("read_file", _read("/hr/deep/dir/prod.env"), True),  # "*.env" anywhere
        ("write_file", {"path": "/engineering/docs/x.env", "content": "x"}, True),
        ("read_file", _read("/expenses/q3.csv"), False),
        ("read_file", _read("/engineering/docs/secrets.md"), False),  # not /engineering/secrets*
        # case-insensitive: /engineering/SECRETS.ENV is the same file on NTFS
        ("read_file", _read("/engineering/SECRETS.ENV"), True),
    ],
)
def test_sensitive_table(policy, tool, args, sensitive):
    assert policy.resolve(tool, args).sensitive is sensitive


def test_case_variant_secret_is_sensitive_but_uncategorized_and_unscoped(policy):
    """Odd casing must not grant access, yet must still arm the exfil rule."""
    action = policy.resolve("read_file", _read("/ENGINEERING/SECRETS.ENV"))
    assert action.sensitive is True
    assert action.category is None
    assert policy.scope_allows(["files:read:/engineering/*"], action) is False


# --------------------------------------------------------------------------------------
# Policy loading fails closed with PolicyConfigError.
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
    pytest.param("actions.yaml", "    tier: low\n", "    tier: lowest\n", id="unknown-tier"),
    pytest.param(
        "actions.yaml",
        "    target_arg: path\n    tier: low\n",
        "    target_arg: path\n    tier: low\n    skip_scope_check: true\n",
        id="unknown-tool-key",
    ),
    pytest.param("actions.yaml", "    args: [path]\n", "", id="missing-args"),
]


@pytest.mark.parametrize(("name", "old", "new"), _CONFIG_EDITS)
def test_bad_policy_config_fails_closed(tmp_path, name, old, new):
    pol_dir = _copy_real_policy(tmp_path)
    _edit(pol_dir, name, old, new)
    with pytest.raises(policy_mod.PolicyConfigError):
        Policy.load(pol_dir)
