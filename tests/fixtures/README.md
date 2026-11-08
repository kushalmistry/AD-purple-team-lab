# Fixtures

One folder per rule, named after the rule file stem:

```
<rule_name>/positive.jsonl   events the rule MUST fire on
<rule_name>/negative.jsonl   benign look-alikes the rule MUST NOT fire on
```

**Status:** the initial fixtures are hand-built from documented event schemas so the
test harness works from day one. Replace or extend them with events exported from the
lab (`scripts/Export-LabEvents.ps1`) as each technique is run, and note the swap in the
rule's write-up.
