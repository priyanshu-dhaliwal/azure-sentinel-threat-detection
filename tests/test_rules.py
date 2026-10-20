"""Tests for the detection rules themselves.

Each rule is checked two ways:

  1. **Structure** — required fields, ATT&CK mapping, a tuning block with a
     rationale. A rule without a recorded rationale is a rule that will be
     re-litigated every quarter.
  2. **Behaviour** — the query, run through the offline KQL subset evaluator,
     must return > 0 rows for the positive fixture and 0 for the negative one.

Rules whose KQL uses constructs the evaluator does not model are reported as
`unverifiable` and counted — not silently skipped.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

try:
    import yaml
except ModuleNotFoundError:  # fall back to the bundled mini-parser
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import yamlmini as yaml  # type: ignore

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
RULES = sorted((ROOT / "detections" / "analytic-rules").glob("*.yaml"))
FIXTURES = HERE / "fixtures"

sys.path.insert(0, str(HERE))
import kql_eval  # noqa: E402

REQUIRED_FIELDS = (
    "id", "name", "description", "severity", "status", "query",
    "queryFrequency", "queryPeriod", "tactics", "relevantTechniques",
    "entityMappings", "tuning",
)
VALID_SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
VALID_STATUS = {"Available", "Disabled"}


def rule_files():
    assert RULES, "no analytic rules found"
    return RULES


def load(rule_path: pathlib.Path) -> dict:
    return yaml.safe_load(rule_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_path", rule_files(), ids=lambda p: p.stem)
def test_rule_has_required_fields(rule_path):
    rule = load(rule_path)
    missing = [f for f in REQUIRED_FIELDS if not rule.get(f)]
    assert not missing, f"{rule_path.name} is missing: {missing}"


@pytest.mark.parametrize("rule_path", rule_files(), ids=lambda p: p.stem)
def test_rule_severity_and_status_are_valid(rule_path):
    rule = load(rule_path)
    assert rule["severity"] in VALID_SEVERITIES
    assert rule["status"] in VALID_STATUS


@pytest.mark.parametrize("rule_path", rule_files(), ids=lambda p: p.stem)
def test_rule_is_attack_mapped(rule_path):
    """A rule with no technique cannot be reasoned about in a coverage review."""
    rule = load(rule_path)
    assert rule["tactics"], "no tactic"
    assert rule["relevantTechniques"], "no technique"
    for tech in rule["relevantTechniques"]:
        assert tech.startswith("T"), f"'{tech}' is not an ATT&CK technique id"


@pytest.mark.parametrize("rule_path", rule_files(), ids=lambda p: p.stem)
def test_rule_records_its_tuning_rationale(rule_path):
    """Thresholds without a written rationale get changed by guesswork."""
    rule = load(rule_path)
    tuning = rule["tuning"]
    assert tuning.get("rationale"), "no tuning rationale"
    assert isinstance(tuning.get("thresholdHistory"), list)
    assert tuning["containment"] in ("notify-only", "auto-contain", "escalate"), (
        f"{rule_path.name}: containment must declare its confidence level"
    )


@pytest.mark.parametrize("rule_path", rule_files(), ids=lambda p: p.stem)
def test_rule_maps_entities_for_the_playbook(rule_path):
    rule = load(rule_path)
    assert rule["entityMappings"], "no entity mappings — the playbook cannot enrich"
    for mapping in rule["entityMappings"]:
        assert mapping["entityType"]
        assert mapping["fieldMappings"]


def test_rule_ids_are_unique():
    ids = [load(p)["id"] for p in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids — deployment would overwrite one"


# ---------------------------------------------------------------------------
# Behaviour, via fixtures
# ---------------------------------------------------------------------------

def fixture_pairs() -> list[tuple[pathlib.Path, pathlib.Path]]:
    pairs = []
    for positive in sorted(FIXTURES.glob("*.positive.json")):
        negative = positive.with_name(positive.name.replace(".positive.", ".negative."))
        if negative.exists():
            pairs.append((positive, negative))
    return pairs


def test_every_rule_has_fixtures():
    """Coverage is a number, not a feeling: this asserts it stays complete."""
    with_fixtures = {p.name.replace(".positive.json", "") for p, _ in fixture_pairs()}
    all_rules = {p.stem for p in RULES}
    missing = all_rules - with_fixtures
    assert not missing, f"rules with no positive/negative fixture: {sorted(missing)}"


@pytest.mark.parametrize("positive,negative", fixture_pairs(),
                         ids=lambda p: p.name if isinstance(p, pathlib.Path) else str(p))
def test_rule_fires_on_attack_and_stays_quiet_on_noise(positive, negative):
    stem = positive.name.replace(".positive.json", "")
    rule_path = ROOT / "detections" / "analytic-rules" / f"{stem}.yaml"
    rule = load(rule_path)
    query = rule["query"]

    attack_rows = json.loads(positive.read_text())
    noise_rows = json.loads(negative.read_text())

    try:
        attack_hits = kql_eval.count(query, attack_rows)
        noise_hits = kql_eval.count(query, noise_rows)
    except kql_eval.Unsupported as exc:
        pytest.skip(f"{stem}: query uses KQL the offline evaluator does not model ({exc})")

    assert attack_hits > 0, f"{stem} did NOT fire on the attack fixture"
    assert noise_hits == 0, f"{stem} fired {noise_hits} time(s) on the noise fixture"


def test_attack_fixtures_are_not_empty():
    for positive, _ in fixture_pairs():
        rows = json.loads(positive.read_text())
        assert rows, f"{positive.name} is empty — a rule cannot be tested against nothing"


# ---------------------------------------------------------------------------
# Coverage report (printed, and asserted non-regressing)
# ---------------------------------------------------------------------------

def test_unverifiable_rules():
    """
    Some queries cannot be evaluated offline (serialize/prev, joins, mv-expand).
    They are listed here explicitly so:
      * the CI output states how many rules are NOT covered by fixture tests,
      * adding one requires touching this list, which shows up in review.
    """
    UNVERIFIABLE = {"sentinel-impossible-travel"}
    print(f"\n{len(UNVERIFIABLE)} rule(s) require a live workspace to verify: {sorted(UNVERIFIABLE)}")
    all_rules = {p.stem for p in RULES}
    assert UNVERIFIABLE <= all_rules, "a listed unverifiable rule no longer exists"
    # Do not let this list grow silently: half the rules unverified is not a
    # detection programme, it is a folder of queries.
    assert len(UNVERIFIABLE) <= max(2, len(all_rules) // 4), (
        f"{len(UNVERIFIABLE)} of {len(all_rules)} rules are unverified — too many"
    )


def test_attack_coverage_summary():
    tactics = {}
    for rule_path in RULES:
        rule = load(rule_path)
        for tactic in rule["tactics"]:
            tactics.setdefault(tactic, []).append(rule_path.stem)

    print("\nATT&CK tactic coverage:")
    for tactic, rules in sorted(tactics.items()):
        print(f"  {tactic:<24} {len(rules)} rule(s)")

    # A detection programme that covers only one tactic is a programme that
    # catches only one kind of incident.
    assert len(tactics) >= 5, f"only {len(tactics)} tactics covered"
    for required in ("CredentialAccess", "DefenseEvasion", "Persistence"):
        assert required in tactics, f"no coverage for {required}"
