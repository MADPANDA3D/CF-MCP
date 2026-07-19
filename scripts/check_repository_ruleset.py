#!/usr/bin/env python3
"""Validate the exact public-main repository ruleset contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-json", type=Path, required=True)
    parser.add_argument("--branch-json", type=Path, required=True)
    parser.add_argument("--rulesets-json", type=Path, required=True)
    parser.add_argument("--ruleset-json", type=Path, required=True)
    parser.add_argument("--effective-rules-json", type=Path, required=True)
    parser.add_argument("--expected-config", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--default-branch", required=True)
    parser.add_argument(
        "--allow-hidden-bypass-actors",
        action="store_true",
        help=(
            "Allow GitHub to omit bypass_actors for a read-only workflow token. "
            "Owner-token provisioning/readback must run without this option."
        ),
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonstandard_number(value: str) -> None:
    raise ValueError(f"nonstandard JSON number: {value}")


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonstandard_number,
    )


def load_object(path: Path, label: str) -> dict[str, Any]:
    value = load_json(path)
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def load_array(path: Path, label: str) -> list[Any]:
    value = load_json(path)
    require(isinstance(value, list), f"{label} must be a JSON array")
    return value


def object_value(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def array_value(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be a JSON array")
    return value


def string_set(value: Any, label: str) -> set[str]:
    items = array_value(value, label)
    require(all(isinstance(item, str) for item in items), f"{label} must contain strings")
    result = set(items)
    require(len(result) == len(items), f"{label} must not contain duplicates")
    return result


def index_rules(value: Any, label: str) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for index, raw_rule in enumerate(array_value(value, label)):
        rule = object_value(raw_rule, f"{label}[{index}]")
        rule_type = rule.get("type")
        require(isinstance(rule_type, str) and rule_type, f"{label}[{index}].type is invalid")
        require(rule_type not in rules, f"{label} contains duplicate rule type {rule_type}")
        rules[rule_type] = rule
    return rules


def status_checks(rule: dict[str, Any], label: str) -> dict[str, int | None]:
    parameters = object_value(rule.get("parameters"), f"{label}.parameters")
    raw_checks = array_value(
        parameters.get("required_status_checks"),
        f"{label}.parameters.required_status_checks",
    )
    checks: dict[str, int | None] = {}
    for index, raw_check in enumerate(raw_checks):
        check = object_value(raw_check, f"{label}.required_status_checks[{index}]")
        context = check.get("context")
        require(
            isinstance(context, str) and context,
            f"{label}.required_status_checks[{index}].context is invalid",
        )
        integration_id = check.get("integration_id")
        require(
            integration_id is None
            or (isinstance(integration_id, int) and not isinstance(integration_id, bool)),
            f"{label}.required_status_checks[{index}].integration_id is invalid",
        )
        require(context not in checks, f"{label} contains duplicate status context {context}")
        checks[context] = integration_id
    return checks


def validate_rule_contract(expected_value: Any, observed_value: Any, label: str) -> None:
    expected_rules = index_rules(expected_value, "expected.rules")
    observed_rules = index_rules(observed_value, label)
    required_rule_types = {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
    require(
        set(expected_rules) == required_rule_types,
        "expected config must contain the exact public-main rule types",
    )
    require(
        set(observed_rules) == set(expected_rules),
        f"{label} rule types mismatch: "
        f"expected={sorted(expected_rules)} observed={sorted(observed_rules)}",
    )

    expected_pull_request = object_value(
        expected_rules["pull_request"].get("parameters"),
        "expected.pull_request.parameters",
    )
    observed_pull_request = object_value(
        observed_rules["pull_request"].get("parameters"),
        f"{label}.pull_request.parameters",
    )
    for key in (
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "required_review_thread_resolution",
    ):
        require(isinstance(expected_pull_request.get(key), bool), f"expected {key} must be boolean")
        require(isinstance(observed_pull_request.get(key), bool), f"observed {key} must be boolean")
        require(
            observed_pull_request[key] is expected_pull_request[key],
            f"pull request rule mismatch for {key}",
        )
    expected_review_count = expected_pull_request.get("required_approving_review_count")
    observed_review_count = observed_pull_request.get("required_approving_review_count")
    require(
        isinstance(expected_review_count, int) and not isinstance(expected_review_count, bool),
        "expected required_approving_review_count must be an integer",
    )
    require(
        isinstance(observed_review_count, int) and not isinstance(observed_review_count, bool),
        "observed required_approving_review_count must be an integer",
    )
    require(
        observed_review_count == expected_review_count,
        "pull request rule mismatch for required_approving_review_count",
    )
    require(
        string_set(
            observed_pull_request.get("allowed_merge_methods"),
            f"{label}.pull_request.allowed_merge_methods",
        )
        == string_set(
            expected_pull_request.get("allowed_merge_methods"),
            "expected.pull_request.allowed_merge_methods",
        ),
        "pull request merge methods mismatch",
    )

    expected_status = expected_rules["required_status_checks"]
    observed_status = observed_rules["required_status_checks"]
    expected_status_parameters = object_value(
        expected_status.get("parameters"), "expected.required_status_checks.parameters"
    )
    observed_status_parameters = object_value(
        observed_status.get("parameters"), f"{label}.required_status_checks.parameters"
    )
    require(
        expected_status_parameters.get("strict_required_status_checks_policy") is True,
        "expected required status checks must use strict policy",
    )
    require(
        expected_status_parameters.get("do_not_enforce_on_create") is False,
        "expected required status checks must apply when branches are created",
    )
    require(
        observed_status_parameters.get("strict_required_status_checks_policy")
        is expected_status_parameters.get("strict_required_status_checks_policy"),
        "required status checks must use strict policy",
    )
    require(
        observed_status_parameters.get("do_not_enforce_on_create")
        is expected_status_parameters.get("do_not_enforce_on_create"),
        "required status checks must apply when branches are created",
    )
    expected_checks = status_checks(expected_status, "expected.required_status_checks")
    observed_checks = status_checks(observed_status, f"{label}.required_status_checks")
    require(
        observed_checks.keys() == expected_checks.keys(),
        f"{label} status check contexts mismatch: "
        f"expected={sorted(expected_checks)} observed={sorted(observed_checks)}",
    )
    for context, integration_id in expected_checks.items():
        require(
            observed_checks[context] == integration_id,
            f"{label} status check {context} has the wrong integration id",
        )


def validate_ruleset(
    *,
    repository: dict[str, Any],
    branch: dict[str, Any],
    summaries: list[Any],
    ruleset: dict[str, Any],
    effective_rules: list[Any],
    expected: dict[str, Any],
    repository_name: str,
    default_branch: str,
    allow_hidden_bypass_actors: bool,
) -> None:
    require(repository.get("full_name") == repository_name, "repository identity mismatch")
    require(repository.get("visibility") == "public", "repository must be public")
    require(repository.get("default_branch") == default_branch, "default branch mismatch")
    require(branch.get("name") == default_branch, "branch identity mismatch")
    require(branch.get("protected") is True, "default branch is not protected")

    expected_name = expected.get("name")
    require(isinstance(expected_name, str) and expected_name, "expected ruleset name is invalid")
    expected_target = expected.get("target")
    expected_enforcement = expected.get("enforcement")
    require(expected_target == "branch", "expected ruleset must target branches")
    require(expected_enforcement == "active", "expected ruleset must be active")
    require(expected.get("bypass_actors") == [], "expected ruleset must not allow bypasses")

    ruleset_id = ruleset.get("id")
    require(
        isinstance(ruleset_id, int) and not isinstance(ruleset_id, bool) and ruleset_id > 0,
        "ruleset id is invalid",
    )
    matching_summaries = []
    for index, raw_summary in enumerate(summaries):
        summary = object_value(raw_summary, f"rulesets[{index}]")
        if (
            summary.get("name") == expected_name
            and summary.get("source_type") == "Repository"
            and summary.get("source") == repository_name
        ):
            matching_summaries.append(summary)
    require(len(matching_summaries) == 1, "exact repository ruleset summary is not unique")
    require(matching_summaries[0].get("id") == ruleset_id, "ruleset summary id mismatch")

    require(ruleset.get("name") == expected_name, "ruleset name mismatch")
    require(ruleset.get("target") == expected_target, "ruleset target mismatch")
    require(ruleset.get("source_type") == "Repository", "ruleset must be repository-owned")
    require(ruleset.get("source") == repository_name, "ruleset source mismatch")
    require(ruleset.get("enforcement") == expected_enforcement, "ruleset is not active")
    if "bypass_actors" in ruleset:
        require(ruleset["bypass_actors"] == [], "ruleset bypass actors must be empty")
    else:
        require(
            allow_hidden_bypass_actors,
            "ruleset bypass actors must be visible for owner-token verification",
        )
    require(
        ruleset.get("current_user_can_bypass") == "never",
        "current API identity can bypass the ruleset",
    )

    expected_conditions = object_value(expected.get("conditions"), "expected.conditions")
    observed_conditions = object_value(ruleset.get("conditions"), "ruleset.conditions")
    expected_ref_name = object_value(expected_conditions.get("ref_name"), "expected.ref_name")
    observed_ref_name = object_value(observed_conditions.get("ref_name"), "ruleset.ref_name")
    require(
        string_set(observed_ref_name.get("include"), "ruleset.ref_name.include")
        == string_set(expected_ref_name.get("include"), "expected.ref_name.include"),
        "ruleset include conditions mismatch",
    )
    require(
        string_set(observed_ref_name.get("exclude"), "ruleset.ref_name.exclude")
        == string_set(expected_ref_name.get("exclude"), "expected.ref_name.exclude"),
        "ruleset exclude conditions mismatch",
    )

    validate_rule_contract(expected.get("rules"), ruleset.get("rules"), "ruleset.rules")

    rules_from_exact_ruleset: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(effective_rules):
        rule = object_value(raw_rule, f"effective_rules[{index}]")
        if rule.get("ruleset_id") != ruleset_id:
            continue
        require(
            rule.get("ruleset_source_type") == "Repository",
            "effective rule source type mismatch",
        )
        require(rule.get("ruleset_source") == repository_name, "effective rule source mismatch")
        rules_from_exact_ruleset.append(rule)
    validate_rule_contract(expected.get("rules"), rules_from_exact_ruleset, "effective_rules")


def main() -> None:
    args = parse_args()
    try:
        validate_ruleset(
            repository=load_object(args.repository_json, "repository"),
            branch=load_object(args.branch_json, "branch"),
            summaries=load_array(args.rulesets_json, "rulesets"),
            ruleset=load_object(args.ruleset_json, "ruleset"),
            effective_rules=load_array(args.effective_rules_json, "effective rules"),
            expected=load_object(args.expected_config, "expected config"),
            repository_name=args.repository,
            default_branch=args.default_branch,
            allow_hidden_bypass_actors=args.allow_hidden_bypass_actors,
        )
    except (AssertionError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"repository ruleset validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(f"{args.repository} public {args.default_branch} satisfies the exact ruleset contract.")


if __name__ == "__main__":
    main()
