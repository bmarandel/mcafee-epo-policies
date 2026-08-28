# Examples

Short, runnable scripts showing how to use `mcafee_epo_policies` against a
real policy exported from the ePO Policy Catalog. Each script expects its
own single-policy XML export (the same shape you get from extracting one
policy out of a `Policies` collection, or from `Policy.load_from_file`).

- **`agent_general_repository.py`** - McAfee Agent General and Repository
  policies: read/adjust communication intervals, reorder and enable/disable
  repositories.
- **`on_access_scan.py`** - ENS Threat Prevention On-Access Scan: read
  settings, raise GTI sensitivity, add a folder exclusion.
- **`on_demand_scan.py`** - ENS Threat Prevention On-Demand Scan: add a Full
  Scan location and a file type exclusion.
- **`firewall_rules.py`** - ENS Firewall: export the rule tree as a Markdown
  report (read-only - rule editing isn't supported yet).

Run any script with `-h`-style usage by calling it without arguments, e.g.:

```
python3 examples/on_access_scan.py my_oas_policy.xml
```

Each script writes its result next to where you run it (e.g.
`oas_updated.xml`) - it never overwrites the input file.
