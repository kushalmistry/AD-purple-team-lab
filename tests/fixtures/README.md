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

## Provenance

For `kerberoasting_rc4_tgs_request`, `asrep_roasting_no_preauth` and
`dcsync_replication_by_non_dc`, the positive fixtures and most negatives are real
events captured from the Hyper-V lab and exported with `scripts/Export-LabEvents.ps1`.
The other rules still use the hand-built fixtures described above.

A few negative records are synthetic edge cases. Each is clearly marked with a `_note`
field, and they were added to exercise exclusion filters that normal lab traffic did
not trigger:

- `kerberoasting_rc4_tgs_request`: RC4 service tickets for a machine account and for
  `krbtgt`, which the rule must filter out.
- `dcsync_replication_by_non_dc`: replication by an Entra Connect sync account
  (`MSOL_*`), which is legitimate and must be filtered out.
