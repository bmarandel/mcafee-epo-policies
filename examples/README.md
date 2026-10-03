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
- **`set-proc-exclusions.py`** - ENS Threat Prevention On-Access Scan: bulk
  utility that reads a plain text list of process names or full paths (one
  per line), adds each `.exe` as "Low Risk" in the policy's Process
  Settings, and makes sure the Low Risk profile is set to skip scanning
  entirely. Takes two arguments - see `python3 examples/set-proc-exclusions.py -h`.

- **`solidcore_application_control.py`** - Solidcore Application Control
  Rules (Windows): from a full Solidcore export, list the policies, then copy
  one (keeping its shared Rule Groups) with an updater, a trusted directory
  and an execution control rule added. Takes two arguments - the export file
  and the name of the policy to copy.

- **`solidcore_rule_groups.py`** - Solidcore Rule Groups: create a user
  defined Application Control Rule Group and make a policy use it; writes
  `rule_group.xml` (for `scor.rulegroup.import`) and `policy.xml` (for
  `policy.importPolicy`, after the Rule Group). Takes three arguments - the
  Solidcore export, the policy name and the new Rule Group name.

### Working directly against ePO (Solidcore)

These scripts export and import policies and Rule Groups with the ePO API,
through the "mcafee-epo" client (`pip install mcafee-epo`, or
`pip install mcafee_epo_policies[examples]`) and the shared helper
`epo_solidcore.py`. Set the connection with `--url`/`--user` or the
`EPO_URL`/`EPO_USER`/`EPO_PASSWORD` environment variables (the password is
asked if not set); `--insecure` skips the server certificate check (lab
servers), `--dry-run` only writes the XML files. They can be run again: they
update what the previous run created.

- **`solidcore_app_control_sample.py`** - retrieves the Application Control
  Rules (Windows) policy "App CTRL Windows Sample" (created with the Trellix
  and Windows Update Rule Groups if missing), adds one example item in each
  tab (updaters, certificate with `--certificate`, installer, directory, user,
  executable files, exclusion, filters, execution control), creates a
  "Sample - Microsoft SQL Server" Rule Group and adds it to the policy.
- **`solidcore_fim_windows_critical_files.py`** - creates the Integrity
  Monitoring Rules (Windows) policy "FIM Windows Server 2019 Sample" from a
  blank policy, with the Trellix "Windows 2019 Server (64 bit) Base Filters"
  Rule Group and a new "Windows Critical Config Files" Rule Group: Windows
  configuration and data files worth monitoring (no executables), with the
  reasons documented in the script.
- **`solidcore_change_control_critical_files.py`** - creates the Change
  Control Rules (Windows) policy "CC Windows Critical Files Sample" from some
  files of "Windows Critical Config Files" (run the FIM script first):
  write-protects the name resolution files and the Run/RunOnce registry
  keys. Read-Protect is deliberately not used: it is disabled by default
  because of its impact on the system performance.

Run any script with `-h`-style usage by calling it without arguments, e.g.:

```
python3 examples/on_access_scan.py my_oas_policy.xml
```

Each script writes its result next to where you run it (e.g.
`oas_updated.xml`) - it never overwrites the input file.
