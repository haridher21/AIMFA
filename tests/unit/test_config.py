"""Settings: relative directories are anchored at the repo root, not the cwd."""

from __future__ import annotations

from pathlib import Path

from aimfa.common.config import REPO_ROOT, Settings


def test_relative_dirs_resolve_against_repo_root_from_any_cwd(tmp_path, monkeypatch):
    """`.env` says DATA_DIR=./var. Running `python run_demo.py` from scripts/ must still
    use <repo>/var, or --reset is refused and services would split across two databases."""
    monkeypatch.chdir(tmp_path)
    s = Settings(_env_file=None, data_dir=Path("./var"), keys_dir=Path("keys"))
    assert s.data_dir.resolve() == (REPO_ROOT / "var").resolve()
    assert s.keys_dir.resolve() == (REPO_ROOT / "keys").resolve()


def test_absolute_dirs_are_kept(tmp_path):
    s = Settings(_env_file=None, data_dir=tmp_path / "data")
    assert s.data_dir == tmp_path / "data"
