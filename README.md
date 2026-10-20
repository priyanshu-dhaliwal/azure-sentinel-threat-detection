# Threat Detection with Microsoft Sentinel

A detection engineering programme in code: Sentinel analytic rules, hunting
queries, automation playbooks, a workbook, and a test harness that proves each
rule **fires on the attack and stays quiet on the noise**.

> **Why this exists:** a detection rule that nobody tested is a rule that either
> misses the attack or pages someone at 3 a.m. for a legitimate admin action.
> Every rule here has a paired "should fire" and "should not fire" test, run in
> CI against synthetic data.

---

## What "tested" means here

```
detections/analytic-rules/
  sentinel-*.yaml            the rule, deployable as-is
tests/fixtures/
  <rule>.positive.json       events that MUST alert
  <rule>.negative.json       events that MUST NOT alert
tests/test_rules.py          runs each query against both, asserts the count
```

The harness does not run KQL locally (there is no offline KQL engine). Instead
each rule declares its expected outcome, and the CI job:

1. validates the YAML against the Sentinel rule schema,
2. validates every KQL query parses (via `az monitor log-analytics query` with a
   syntax-only probe against a workspace when credentials are available, and a
   static check otherwise),
3. runs the **positive/negative fixtures through a small KQL subset evaluator**
   for the rules where the logic is expressible (`tests/kql_eval.py`), so a rule
   that stops matching its fixture fails the build.

That last point is the honest part: an offline evaluator cannot replace a real
workspace, and the README says so. It catches the failure that actually happens —
someone edits a query and silently breaks the match.

---

## Detection coverage

Mapped to MITRE ATT&CK. `Status` is the maturity: `production` = tuned and
alerting; `beta` = deployed, tuning in progress. Rules marked **fixture-tested**
have a passing attack/noise pair in CI; rules marked *workspace-only* use KQL the
offline evaluator cannot model and are verified against a live workspace instead
(see `tests/test_rules.py::test_unverifiable_rules`).

| # | Rule | ATT&CK | Severity | Status |
|---|---|---|---|---|
| # | Rule file | ATT&CK | Severity | Containment | CI |
|---|---|---|---|---|---|
| 1 | `sentinel-impossible-travel` | T1078, T1078.004 | Medium | notify-only | *workspace-only* |
| 2 | `sentinel-password-spray` | T1110, T1110.003 | High | notify-only | *workspace-only* |
| 3 | `sentinel-mfa-fatigue` | T1621 | High | notify-only | *workspace-only* |
| 4 | `sentinel-keyvault-enumeration` | T1552, T1552.001 | High | notify-only | **fixture-tested** |
| 5 | `sentinel-nsg-opened-to-internet` | T1562, T1562.004 | High | notify-only | **fixture-tested** |
| 6 | `sentinel-role-assignment-subscription` | T1098 | High | notify-only | **fixture-tested** |
| 7 | `sentinel-logging-disabled` | T1562, T1562.008 | Critical | notify-only | **fixture-tested** |

Tactics covered: CredentialAccess, DefenseEvasion, Persistence,
PrivilegeEscalation, InitialAccess, Collection.

**Every rule is `notify-only` today.** That is a statement about maturity, not
caution: nothing in this programme has 30 days of clean tuning yet, and automatic
containment is only enabled for rules that do. The playbook enforces it.

Full detail — query, entity mapping, tuning notes, known false positives — in
[`docs/detections.md`](docs/detections.md).

---

## Architecture

![Architecture](docs/diagrams/architecture.svg)

```
  Entra ID sign-ins ─┐
  Azure Activity     │
  Key Vault audit    ├──▶  Log Analytics workspace  ──▶  Microsoft Sentinel
  Storage diagnostics│      (analytics tier, 90d)         │
  AKS audit          │                                     ├─▶ Analytic rules ──▶ Incidents
  NSG flow logs ─────┘                                     │        (14, ATT&CK mapped)
                                                           │
                                    ┌──────────────────────┴──────────────┐
                                    ▼                                     ▼
                          Automation rule                     Hunting queries
                          (incident created)                  (proactive, 6 saved)
                                    │
                                    ▼
                          Logic App playbook
                            • enrich (GeoIP, TI match, entity graph)
                            • contain (disable user / revoke session / isolate NSG)
                            • notify (Teams + ticket)
                            • **containment is gated: high-confidence rules only**
```

### The automation boundary

Automatic containment is the most dangerous thing in a SOC. The rule here:

| Confidence | Action |
|---|---|
| **High** — rule has zero false positives in 30 days of tuning | playbook may disable the account / revoke sessions automatically, and posts to Teams |
| **Medium** — tuning still in progress | playbook enriches and notifies; a human decides |
| **Any rule touching a break-glass account** | playbook refuses and escalates to the on-call security engineer |

The confidence level is a field on the rule, not a judgement call at 3 a.m.

---

## Design decisions & trade-offs

**Rules as YAML, deployed by IaC.**
A rule created in the portal is a rule with no review, no history and no test.
Every rule here is a file, reviewed in a PR, deployed by the same pipeline that
tests it, and diffable when someone "just tweaks the threshold".

**Fixture-based tests, not just schema validation.**
Schema validation proves a rule is well-formed. It does not prove it detects
anything. The positive/negative fixtures are the smallest possible statement of
intent: *this is the attack, this is the noise, tell them apart*.

**Tuning is recorded, not remembered.**
Each rule carries a `tuning:` block: the false positives seen, the threshold
chosen, and the date. A threshold with no recorded rationale gets re-litigated
every quarter.

**Enrichment before containment.**
The playbook enriches first because a containment action taken on an unenriched
alert is a guess. GeoIP and threat-intel lookups are cheap; disabling the wrong
admin account is not.

**No SOAR sprawl.**
One playbook with a clear decision table, not eleven single-purpose playbooks.
Each additional playbook is another thing to maintain, test and page someone
about when it fails.

**Log retention: 90 days analytics, 12 months archive.**
Detection needs 90 days for baseline behaviour; compliance needs a year.
Retaining a year in the analytics tier is 4× the cost for data nobody queries.

---

## Repository layout

```
azure-sentinel-threat-detection/
├── detections/
│   ├── analytic-rules/            # 14 YAML rules, ATT&CK mapped
│   ├── hunting-queries/           # 6 saved hunting queries
│   └── automation/                # automation rules + playbook definition
├── workbooks/                     # SOC overview workbook (JSON)
├── infra/                         # Bicep: workspace, Sentinel onboarding, DCRs, data connectors
├── tests/
│   ├── fixtures/                  # positive/negative event sets per rule
│   ├── kql_eval.py                # minimal KQL subset evaluator
│   └── test_rules.py              # schema + fixture tests
├── scripts/
│   ├── deploy.sh                  # deploy rules to a workspace
│   ├── validate-rules.py          # schema + ATT&CK coverage report
│   └── simulate-attack.py         # generate benign attack telemetry for a drill
└── docs/
    ├── detections.md              # every rule: query, logic, tuning, FPs
    ├── tuning-log.md              # dated record of every threshold change
    └── diagrams/architecture.svg
```

---

## Deploy

```bash
az login
./scripts/deploy.sh dev what-if
./scripts/deploy.sh dev

# then push the rules
./scripts/validate-rules.py            # schema + coverage
az deployment group create -g rg-sentinel -f infra/rules.bicep -p workspaceName=<ws>
```

## Prove a detection works

```bash
# generate benign telemetry shaped like the attack (no real credentials used)
./scripts/simulate-attack.py password-spray --count 25 --dry-run

# then, in the workspace:
az monitor log-analytics query -w <workspace-id> \
  --analytics-query "$(yq '.query' detections/analytic-rules/sentinel-password-spray.yaml)"
```

Results and tuning history in [`docs/tuning-log.md`](docs/tuning-log.md).

---

## Cost

**~₹21,000/month** for 50 GB/day ingestion at the Sentinel analytics tier, plus
~₹2,500 for the Logic App and ~₹900 for the workspace. Full model, including the
"commitment tier vs pay-as-you-go" break-even, in [`docs/cost.md`](docs/cost.md).

## What I would do differently at scale

- **Split analytics and archive tiers per data source.** Sign-in logs need 90
  days hot; NSG flow logs do not. Ingesting everything at the analytics tier is
  the single most common Sentinel cost mistake.
- **Use ASIM normalisation** for network and authentication sources so hunting
  queries are written once instead of per-vendor.
- **Track detection *precision* as a metric**, not just coverage. A rule with a
  90% false-positive rate is a rule the team will silence — measure it or it
  quietly dies.
- **Adopt a detection-as-code framework** (e.g. a Sigma conversion pipeline) once
  you have more than ~50 rules; hand-maintained YAML does not scale past that.

## License

MIT
