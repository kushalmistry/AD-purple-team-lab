# <Detection title>

| Field | Value |
|---|---|
| Rule | `detections/<rule>.yml` |
| ATT&CK | Txxxx.xxx - Name |
| Severity | medium |
| Data source | Windows Security 4769 (DC) |
| Status | experimental / tested in lab |

## What it detects
One or two sentences on the behavior, not the tool.

## Why it works
What telemetry artifact the technique leaves behind and why benign activity rarely looks the same.

## Lab validation
- Date run:
- Technique performed from: TCM PEH, section "<name>"
- Result: fired / did not fire (screenshot of the event in `docs/img/`)
- Fixture: `tests/fixtures/<rule>/positive.jsonl`

## False positives and tuning
- Known benign sources and the filter used for each.

## Blind spots
- Variants this rule will NOT catch (e.g. AES-only requests), and what would.

## Response
First three triage steps an analyst should take when this fires.

## Hardening
The configuration change that prevents the technique entirely.
