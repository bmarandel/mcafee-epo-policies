# McAfee ePolicy Orchestrator Policies Python Class Library

![PyPI](https://img.shields.io/pypi/v/mcafee_epo_policies)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-alpha-orange)
![License](https://img.shields.io/github/license/bmarandel/mcafee-epo-policies)
![Top language](https://img.shields.io/github/languages/top/bmarandel/mcafee-epo-policies)

## Overview

This package provides a set of Python classes to read, inspect, and modify policy
documents exported from the Policy Catalog of McAfee ePolicy Orchestrator (ePO),
without needing to know the underlying XML schema. Each supported policy is
exposed as an object with named properties (e.g. `policy.asci = 15`) instead of
raw Section/Setting XML lookups.

## Supported policies

| Product | Policy | Status |
|---|---|---|
| McAfee Agent | General | Full read/write |
| McAfee Agent | Repository | Full read/write |
| McAfee Agent | Troubleshooting | Full read/write |
| McAfee Agent | Custom Properties | Full read/write |
| McAfee Agent | Product Improvement Program (Telemetry) | Full read/write |
| ENS Threat Prevention | On-Access Scan | Full read/write |
| ENS Threat Prevention | On-Demand Scan | Full read/write |
| ENS Threat Prevention | Exploit Prevention | Partial (signatures/expert rules full read/write; application rules read + enable/disable; process exclusions not yet implemented) |
| ENS Firewall | Rules | Read-only / reporting (editing not yet implemented) |
| Solidcore - General | Configuration (Client) | Full read/write (CLI password: raw hashes only) |
| Solidcore - General | Exception Rules (Windows/Unix) | Full read/write |
| Solidcore - Application Control | Application Control Options (Windows/Unix) | Full read/write |
| Solidcore - Application Control | Application Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed |
| Solidcore - Change Control | Change Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed |
| Solidcore - Integrity Monitor | Integrity Monitoring Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed |
| Solidcore | Rule Groups (Application Control, Change Control, Integrity Monitor) | Full read/write of the `scor.rulegroup.export` / `import` files |

McAfee Agent policy coverage is complete - all 5 McAfee Agent policy types are implemented.

Solidcore (Trellix Application and Change Control) policy coverage is complete -
all 13 Solidcore policy types of the ePO Policy Catalog are implemented, in the
`sc` subpackage (`sc.gen`, `sc.awl`, `sc.cc`, `sc.fim`, named after the ePO
feature IDs SCOR_GEN, SCOR_AWL, SCOR_CC and SCOR_FIM).

## Installation

```
pip install mcafee_epo_policies
```

## Usage

```python
from mcafee_epo_policies import McAfeeAgentPolicies, McAfeeAgentPolicyGeneral

# Load a Policies export (XML) from the ePO Policy Catalog
with open('EPOAGENTMETA_policies.xml', 'rb') as f:
    policies = McAfeeAgentPolicies(f.read())

# List the policies contained in the export
print(policies.list())

# Extract one policy and wrap it for editing
policy_xml = policies.get_policy('General', 'My Custom Policy')
policy = McAfeeAgentPolicyGeneral(policy_xml)

# Read and change a setting through a property, instead of raw XML
print(policy.asci)
policy.asci = 15

# Save the edited policy, ready to re-import into ePO
policy.save_to_file('My Custom Policy - edited.xml')
```

### Solidcore

Solidcore policies are exported all together, for every Solidcore feature
(`policy.export productId=SOLIDCORE_META` with the ePO API). Unlike the other
products, a Solidcore policy is a list of rules, plus references to shared Rule
Groups: each tab of the ePO console has its own list methods.

```python
from mcafee_epo_policies import SCPolicies, SCAWLPolicyRules, SCException

with open('SOLIDCORE_META_policies.xml', 'rb') as f:
    policies = SCPolicies(f.read())

# Copy an Application Control Rules policy (shared Rule Groups are kept)
policy = SCAWLPolicyRules(policies.new_policy('AWL Rules (Windows)', 'My Copy',
                                              template='My Rules Policy'))
print(policy.get_rule_group_names())

policy.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
policy.add_exclusion(SCException.CASP, 'legacy.exe')
policy.add_execution_control_rule('powershell.exe', 'block',
                                  [('command_line', 'matches', '.*-enc.*')])
policy.save_to_file('My Copy.xml')
```

#### Solidcore Rule Groups

Rule Groups (Menu > Configuration > Solidcore Rules) are exported and imported
with their own ePO API commands, `scor.rulegroup.export` and
`scor.rulegroup.import` (without a Rule Group name, the export only contains
the user defined Rule Groups). `SCRuleGroups` reads and writes those files, and
each Rule Group is edited with the same methods as the matching policy tabs.

```python
from mcafee_epo_policies import SCRuleGroups, SCAWLPolicyRules

rule_groups = SCRuleGroups()   # or SCRuleGroups(<scor.rulegroup.export output>)
group = rule_groups.new_rule_group('My Apps', SCRuleGroups.APPLICATION_CONTROL,
                                   SCRuleGroups.WINDOWS)
group.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
rule_groups.save_to_file('rule_group.xml')   # scor.rulegroup.import file=rule_group.xml

policy = SCAWLPolicyRules(policies.get_policy('AWL Rules (Windows)', 'My Policy'))
policy.add_rule_group(group)                 # policy.importPolicy, after the Rule Group
```

ePO links a policy to a Rule Group by its name: import the Rule Group before
the policy that uses it. An existing Rule Group is only replaced by
`scor.rulegroup.import` with `override=true` (otherwise the import fails, even
though the API answers success - check the "Import Solidcore Rule Groups"
server task).

Note: ePO stores some Solidcore policies under an internal type name, used as
`type_id` (e.g. `Lockdown Rules` for Configuration (Client), `Attr Rules
(Windows)` for Exception Rules (Windows), `Mon Rules (Unix)` for Integrity
Monitoring Rules (Unix)); `SCPolicies.list()` shows them.

## Examples

The [`examples/`](examples/) directory has short, runnable scripts covering
McAfee Agent (General/Repository), ENS Threat Prevention (On-Access Scan,
On-Demand Scan, process exclusions), ENS Firewall (Rules reporting), and
Solidcore (Application Control, Integrity Monitor and Change Control policies,
Rule Groups - some of them working directly against an ePO server).

## Documentation

There is no separate documentation site yet; every class and method has a
docstring describing which ePO UI setting it maps to.

## Requirements

Python 3.8 or later.

## History

### 0.3.0 - 2026-10-03

**Added**
- Solidcore (Trellix Application and Change Control) support, in the new `sc`
  subpackage - all 13 Solidcore policy types:
  - `sc.gen`: `SCGENPolicyConfiguration` (Configuration (Client)) and
    `SCGENPolicyExceptionRules` (Exception Rules, Windows/Unix);
  - `sc.awl`: `SCAWLPolicyOptions` and `SCAWLPolicyRules` (Application
    Control Options and Rules, Windows/Unix);
  - `sc.cc`: `SCCCPolicyRules` (Change Control Rules, Windows/Unix);
  - `sc.fim`: `SCFIMPolicyRules` (Integrity Monitoring Rules, Windows/Unix);
  - `SCPolicies` (Solidcore export), whose `new_policy()` keeps the shared Rule
    Groups referenced by the template, and the `SCPolicy` base class giving
    generic access to Solidcore rules and Rule Groups;
  - `sc.rulegroups`: `SCRuleGroups` for the Solidcore Rule Groups files of the
    `scor.rulegroup.export` / `scor.rulegroup.import` API commands (create,
    copy, edit user defined Rule Groups), with `SCAWLRuleGroup`,
    `SCCCRuleGroup` and `SCFIMRuleGroup` sharing the policy tab methods, and
    `add_rule_group()` / `remove_rule_group()` to make a policy use a Rule Group.
- `SCException` and `SCReputation` constants classes.
- `SCPolicies.new_empty_policy()`: a new policy without any rule or Rule Group
  (the ePO "Blank Template" can't be exported).
- `examples/solidcore_application_control.py` and
  `examples/solidcore_rule_groups.py`, and three examples working directly
  against an ePO server with the "mcafee-epo" API client (optional dependency
  `pip install mcafee_epo_policies[examples]`): Application Control policy
  with one item per tab and a database Rule Group, Integrity Monitor policy
  with a "Windows Critical Config Files" Rule Group, and Change Control
  policy protecting some of those files.
- Tests built from real ePO 5.10 exports, each policy type also checked end to
  end: edited with the library, imported into ePO, exported back unchanged and
  displayed as expected in the ePO console.

### 0.2.0 - 2026-08-28

**Added**
- Full support for the remaining McAfee Agent policies: Troubleshooting,
  Custom Properties, and Product Improvement Program (Telemetry) - McAfee
  Agent policy coverage is now complete.
- `Language` constants class for the Troubleshooting policy's agent
  language selection (21 languages, LCID codes).
- Two new "Ransomware" options on the On-Access Scan policy:
  `detect_unknown_ransomware` and `ransomware_bait_files`.
- Read support and enable/disable control for Exploit Prevention
  Application Protection Rules (`application_rules_list`,
  `application_rule_get`, `get/set_application_rule_status`,
  `get/set_application_rule_inclusion_status`).
- `signatures_delete()` on the Exploit Prevention policy now actually
  removes an Expert Rule (previously a no-op).
- Validation when `signatures_add()` is called with an explicit `sig_id`:
  rejects IDs that are already in use or outside the valid range.
- Generic `get_indexed_list`/`set_indexed_list`/`get_indexed_table`/
  `set_indexed_table` helpers on the base `Policy` class, replacing eight
  independent hand-written implementations of the same
  "count + indexed settings" XML pattern.
- A `tests/` suite (pytest, 52 tests) built from real ePO policy exports,
  including two structural tests that check the whole package for
  property-wiring and mutable-default-argument mistakes.
- An `examples/` directory with runnable scripts for McAfee Agent,
  On-Access Scan, On-Demand Scan, and Firewall Rules reporting.

**Changed**
- Migrated packaging from `setup.py` to `pyproject.toml` (PEP 621), with an
  SPDX license expression.
- `mcafee_epo_policies.__version__` now reads the installed package
  version via `importlib.metadata`, instead of accidentally reporting the
  version of `setuptools`.

**Fixed**
- Six mismatched `property(getter, setter)` declarations in the McAfee
  Agent General policy that made several settings silently unreadable,
  unwritable, or both.
- `test_cert_authentication` is now correctly read-only, and its
  certificate files are located relative to the package instead of the
  caller's working directory.
- Shared mutable default arguments in `ExclusionList`, `OASProcessList`,
  `OASURLList`, and `ODSLocationList` that could leak state between
  unrelated instances.
- On-Access Scan `process_list`: a key mismatch (`TypeItem_x{row}` vs
  `TypeItem_{row}`) meant a process's risk level set via
  `set_process_list()` could never be read back.
- On-Access Scan `set_process_list([])` no longer leaves the policy in a
  state that crashes the next `get_process_list()` call.
- On-Demand Scan `fs_performance_level`/`qs_performance_level`: a typo
  (`_Performace`) meant the setting was never actually persisted.
- Saving a policy containing any non-ASCII character (accents, curly
  quotes, etc.) produced XML that neither this library nor ePO could
  reliably read back, due to an invalid encoding name.
- `signatures_get()` on the Exploit Prevention policy, previously
  non-functional for any signature.
- The indexed-list/table helpers could leave stale, duplicate settings
  behind when an ePO export already contained orphaned entries beyond
  their declared count - now cleaned up correctly on every write.

### 0.0.6 - 2020-11-25

Starting point for this changelog.

## Bugs and Feedback

For bugs, questions and discussions please use the [GitHub Issues](https://github.com/bmarandel/mcafee-epo-policies/issues).

## License

Copyright 2020 Benjamin Marandel

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License. 
