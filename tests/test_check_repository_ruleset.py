from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_repository_ruleset.py"
EXPECTED_CONFIG = ROOT / ".github" / "rulesets" / "protect-main.json"
REPOSITORY = "MADPANDA3D/CF-MCP"


def _fixture() -> tuple[dict[str, Any], dict[str, Any], list[Any], dict[str, Any]]:
    expected = json.loads(EXPECTED_CONFIG.read_text())
    repository = {
        "full_name": REPOSITORY,
        "visibility": "public",
        "default_branch": "main",
    }
    branch = {"name": "main", "protected": True}
    summary = {
        "id": 42,
        "name": expected["name"],
        "source_type": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
    }
    ruleset = {
        "id": 42,
        **deepcopy(expected),
        "source_type": "Repository",
        "source": REPOSITORY,
        "current_user_can_bypass": "never",
    }
    return repository, branch, [summary], ruleset


def _run(
    tmp_path: Path,
    repository: dict[str, Any],
    branch: dict[str, Any],
    summaries: list[Any],
    ruleset: dict[str, Any],
    *,
    allow_hidden_bypass_actors: bool = False,
    effective_rules: list[Any] | None = None,
) -> subprocess.CompletedProcess[str]:
    paths = {
        "repository": tmp_path / "repository.json",
        "branch": tmp_path / "branch.json",
        "rulesets": tmp_path / "rulesets.json",
        "ruleset": tmp_path / "ruleset.json",
        "effective_rules": tmp_path / "effective-rules.json",
    }
    if effective_rules is None:
        effective_rules = [
            {
                **deepcopy(rule),
                "ruleset_id": ruleset["id"],
                "ruleset_source_type": "Repository",
                "ruleset_source": REPOSITORY,
            }
            for rule in ruleset["rules"]
        ]
    for name, value in (
        ("repository", repository),
        ("branch", branch),
        ("rulesets", summaries),
        ("ruleset", ruleset),
        ("effective_rules", effective_rules),
    ):
        paths[name].write_text(json.dumps(value))
    command = [
        sys.executable,
        str(SCRIPT),
        "--repository-json",
        str(paths["repository"]),
        "--branch-json",
        str(paths["branch"]),
        "--rulesets-json",
        str(paths["rulesets"]),
        "--ruleset-json",
        str(paths["ruleset"]),
        "--effective-rules-json",
        str(paths["effective_rules"]),
        "--expected-config",
        str(EXPECTED_CONFIG),
        "--repository",
        REPOSITORY,
        "--default-branch",
        "main",
    ]
    if allow_hidden_bypass_actors:
        command.append("--allow-hidden-bypass-actors")
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )


def _rule(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any]:
    return next(rule for rule in ruleset["rules"] if rule["type"] == rule_type)


def test_exact_public_main_ruleset_is_accepted(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode == 0, result.stderr
    assert "exact ruleset contract" in result.stdout


def test_hidden_bypass_actors_require_explicit_read_only_mode(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    ruleset.pop("bypass_actors")

    hidden = _run(tmp_path, repository, branch, summaries, ruleset)

    assert hidden.returncode != 0
    assert "visible for owner-token verification" in hidden.stderr

    workflow_readback = _run(
        tmp_path,
        repository,
        branch,
        summaries,
        ruleset,
        allow_hidden_bypass_actors=True,
    )

    assert workflow_readback.returncode == 0, workflow_readback.stderr


def test_nonempty_bypass_actors_are_rejected_in_every_mode(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()

    ruleset["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
    nonempty = _run(
        tmp_path,
        repository,
        branch,
        summaries,
        ruleset,
        allow_hidden_bypass_actors=True,
    )

    assert nonempty.returncode != 0
    assert "must be empty" in nonempty.stderr


def test_api_identity_with_bypass_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    ruleset["current_user_can_bypass"] = "always"

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode != 0
    assert "can bypass" in result.stderr


def test_missing_force_push_or_deletion_rule_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    ruleset["rules"] = [rule for rule in ruleset["rules"] if rule["type"] != "non_fast_forward"]

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode != 0
    assert "rule types mismatch" in result.stderr


def test_duplicate_rule_types_are_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    ruleset["rules"].append({"type": "deletion"})

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode != 0
    assert "duplicate rule type deletion" in result.stderr


def test_unexpected_rule_or_status_check_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    ruleset["rules"].append({"type": "required_signatures"})

    unexpected_rule = _run(tmp_path, repository, branch, summaries, ruleset)

    assert unexpected_rule.returncode != 0
    assert "rule types mismatch" in unexpected_rule.stderr

    repository, branch, summaries, ruleset = _fixture()
    status_rule = _rule(ruleset, "required_status_checks")
    status_rule["parameters"]["required_status_checks"].append(
        {"context": "Unexpected", "integration_id": 15368}
    )
    unexpected_check = _run(tmp_path, repository, branch, summaries, ruleset)

    assert unexpected_check.returncode != 0
    assert "status check contexts mismatch" in unexpected_check.stderr


def test_duplicate_repository_ruleset_summaries_are_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    summaries.append({**summaries[0], "id": 43})

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode != 0
    assert "summary is not unique" in result.stderr


def test_missing_or_non_strict_status_check_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    status_rule = _rule(ruleset, "required_status_checks")
    status_rule["parameters"]["required_status_checks"].pop()

    missing = _run(tmp_path, repository, branch, summaries, ruleset)

    assert missing.returncode != 0
    assert "status check contexts mismatch" in missing.stderr

    repository, branch, summaries, ruleset = _fixture()
    status_rule = _rule(ruleset, "required_status_checks")
    status_rule["parameters"]["strict_required_status_checks_policy"] = False
    non_strict = _run(tmp_path, repository, branch, summaries, ruleset)

    assert non_strict.returncode != 0
    assert "strict policy" in non_strict.stderr


def test_status_checks_from_the_wrong_integration_are_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    status_rule = _rule(ruleset, "required_status_checks")
    status_rule["parameters"]["required_status_checks"][0]["integration_id"] = 1

    result = _run(tmp_path, repository, branch, summaries, ruleset)

    assert result.returncode != 0
    assert "wrong integration id" in result.stderr


def test_unprotected_or_wrong_default_branch_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    branch["protected"] = False

    unprotected = _run(tmp_path, repository, branch, summaries, ruleset)

    assert unprotected.returncode != 0
    assert "not protected" in unprotected.stderr

    repository, branch, summaries, ruleset = _fixture()
    repository["default_branch"] = "develop"
    wrong_default = _run(tmp_path, repository, branch, summaries, ruleset)

    assert wrong_default.returncode != 0
    assert "default branch mismatch" in wrong_default.stderr


def test_missing_effective_rule_is_rejected(tmp_path: Path) -> None:
    repository, branch, summaries, ruleset = _fixture()
    effective_rules = [
        {
            **deepcopy(rule),
            "ruleset_id": ruleset["id"],
            "ruleset_source_type": "Repository",
            "ruleset_source": REPOSITORY,
        }
        for rule in ruleset["rules"]
        if rule["type"] != "deletion"
    ]

    result = _run(
        tmp_path,
        repository,
        branch,
        summaries,
        ruleset,
        effective_rules=effective_rules,
    )

    assert result.returncode != 0
    assert "effective_rules rule types mismatch" in result.stderr
