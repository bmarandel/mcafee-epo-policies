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
raw Section/Setting XML lookups. Policies can also be exported as a Markdown
document (`to_markdown()` / `save_markdown()`, see "Policy documentation"
below) to keep a documentation of the enforced security policies.

## Supported policies

| Product | Policy | Status | Markdown report |
|---|---|---|---|
| McAfee Agent | General | Full read/write | Not yet |
| McAfee Agent | Repository | Full read/write | Not yet |
| McAfee Agent | Troubleshooting | Full read/write | Not yet |
| McAfee Agent | Custom Properties | Full read/write | Not yet |
| McAfee Agent | Product Improvement Program (Telemetry) | Full read/write | Not yet |
| ENS Threat Prevention | On-Access Scan | Full read/write | Yes |
| ENS Threat Prevention | On-Demand Scan | Full read/write | Yes |
| ENS Threat Prevention | Exploit Prevention | Full read/write: signatures/expert rules, exclusions, Application Protection Rules (user-defined created/edited/removed, Trellix-defined status/inclusion/executables/notes) | Yes |
| ENS Threat Prevention | Access Protection | Full read/write: rules (user-defined created/edited/removed, Trellix-defined Block/Report/executables/notes), subrules, exclusions | Yes |
| ENS Threat Prevention | Options | Full read/write | Yes |
| ENS Firewall | Rules | Full read/write: rules, groups (sub groups, location, timed group), networks, applications, schedule | Yes |
| ENS Firewall | Options | Full read/write | Yes |
| Solidcore - General | Configuration (Client) | Full read/write (CLI password: raw hashes only) | Not yet |
| Solidcore - General | Exception Rules (Windows/Unix) | Full read/write | Not yet |
| Solidcore - Application Control | Application Control Options (Windows/Unix) | Full read/write | Not yet |
| Solidcore - Application Control | Application Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Not yet |
| Solidcore - Change Control | Change Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Not yet |
| Solidcore - Integrity Monitor | Integrity Monitoring Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Not yet |
| Solidcore | Rule Groups (Application Control, Change Control, Integrity Monitor) | Full read/write of the `scor.rulegroup.export` / `import` files | Not yet |

The "Markdown report" column tells which policy types support the Markdown
export (`to_markdown()` / `save_markdown()`); for the other policy classes
these methods raise `NotImplementedError` for now (`SCRuleGroups` has no
Markdown export method yet).

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

### Policy documentation (Markdown)

Most companies must keep a documentation of the security policies they
enforce (audits, compliance). `to_markdown()` returns a Markdown document of a
policy, as close as possible to the ePO console: a metadata header (product,
policy category, name, ePO server and version, date), a table of contents,
one section per console tab with the console labels, settings as
"Setting | Value" tables, lists (exclusions, signatures, firewall rules...)
as numbered tables, and a document control section (review/approval
sign-off, change history) to fill in. `save_markdown()` writes it to a file.

```python
policy.save_markdown('On-Access Scan - My Custom Policy.md',
                     author='Jane Doe', reviewers=['CISO'])
```

Available for all ENS policy types: Threat Prevention (On-Access Scan,
On-Demand Scan, Exploit Prevention, Access Protection, Options) and Firewall
(Options, and Rules documented as a firewall review: a rule summary numbered
in evaluation order, then one detail card per group/rule). Labels, order and
displayed items were checked against the ePO 5.10 console (e.g. Exploit
Prevention lists the same 486 signatures as the console). See
`examples/policy_documentation.py`.

### ENS Access Protection rules

```python
from mcafee_epo_policies import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
                                 APExecutable, APUserName)

rule = APRule('Block ransomware extensions', block=True, report=True)
rule.add_executable(APExecutable('Backup agent', path='**\\backupagent.exe', inclusion='exclude'))
rule.add_user_name(APUserName('Local\\System', inclusion='exclude'))
rule.add_subrule(APSubRule('Ransomware extensions', APSubRule.FILES, ['create', 'rename'],
                           targets=[APTarget('*.locky'), APTarget('*.lockbit')]))
policy.add_rule(rule)                                  # policy: ESTPPolicyAccessProtection
policy.set_rule_block('PREVENT_MIMIKATZ_CREATION', '1')  # Trellix-defined rule
```

Subrule types and operation codes are listed in `APSubRule.OPERATIONS` (Windows)
and `APSubRule.LINUX_OPERATIONS` (Linux rules), with the console labels.

### ENS Firewall rules

```python
from mcafee_epo_policies import (FWRule, FWGroup, FWNetwork, FWApplication, FWExecutable,
                                 FWLocation, FWAddress)

rule = FWRule('Allow backup server', FWRule.ALLOW, FWRule.OUT, log=True,
              transport_protocol=FWRule.TCP, remote_ports=['443', '8400-8410'],
              remote_networks=[FWNetwork('Backup servers', ['10.10.0.0/24', 'backup.example.com'])],
              applications=[FWApplication('Backup agent', [
                  FWExecutable('agent', path='**\\backupagent.exe', signer='CN=Example Corp')])])
rule.set_schedule(['Monday', 'Friday'], '20:00', '23:59')
group = FWGroup('Office', location=FWLocation('Office LAN', dns_suffixes=['corp.example.com'],
                                             default_gateways=['10.0.0.1']),
                rules=[rule])
policy.add_rule(group, position=1)                    # policy: ESFWPolicyRules
policy.move_rule('Allow SNMP traffic', group, 0)
snmp = policy.get_rule('Allow SNMP traffic')
snmp.enabled = False
policy.update_rule(snmp)
policy.remove_rule('Allow all outbound traffic on high UDP ports')
```

Addresses are written as in the console (single IP, subnet, range, FQDN, IPv6,
or `FWAddress.LOCAL_SUBNET`, `TRUSTED`, `ANY_IPV4`, `ANY_IPV6`). Rules and groups
locked by the catalog (shown with a "View" link in the console, e.g. "Trellix
core networking") can't be changed. See `examples/firewall_rule_editing.py`.

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
On-Demand Scan, process exclusions), ENS Firewall (Rules reporting and editing), and
Solidcore (Application Control, Integrity Monitor and Change Control policies,
Rule Groups - some of them working directly against an ePO server).

## Documentation

There is no separate documentation site yet; every class and method has a
docstring describing which ePO UI setting it maps to.

## Requirements

Python 3.8 or later.

## History

### 0.5.0 - 2026-10-03

**Added**
- Exploit Prevention exclusions, full read/write: `EPExclusion` (one class
  method per Exclusion Type of the console: `illegal_api()`,
  `file_process_registry()`, `service()`, `network_ips()`, `linux()`, with
  the console checks) and `EPExecutable` (process / caller module: path, MD5,
  signer); `get_exclusions()`, `set_exclusions()`, `add_exclusion()`,
  `remove_exclusion()` on `ESTPPolicyExploitPrevention`. Every section kept
  by ePO for current and older clients is written. Storage learnt from
  exclusions created in the ePO 5.10 console; a policy built by the library
  was imported, displayed and exported back unchanged.
- Exploit Prevention Application Protection Rules, full read/write:
  `EPAppRule` (Name, Status, Inclusion Status, Executables as
  `APExecutable`, Notes) and `get_application_rules()`,
  `get_application_rule()`, `add_application_rule()`,
  `update_application_rule()`, `remove_application_rule()`. User-defined
  rules can be created and removed; for Trellix-defined rules, as in the
  console, everything but the name can be changed. Storage learnt from rules
  created in the ePO 5.10 console; a policy with a rule added and a
  Trellix-defined rule changed by the library was imported, displayed as
  expected and both rules were exported back unchanged (on import ePO gives
  new executable IDs and dates to the untouched Trellix-defined rules). See
  `examples/exploit_prevention.py`.
- ENS Firewall Rules, full read/write: the rule tree as objects (`FWRule`,
  `FWGroup` with its rules, location `FWLocation` and timed group setting,
  `FWNetwork` local/remote networks, `FWApplication` and `FWExecutable`,
  schedule, `FWAddress` for the console address forms) and `get_rules()`,
  `get_all_rules()`, `get_rule()`, `add_rule()`, `update_rule()`,
  `remove_rule()`, `move_rule()` on `ESFWPolicyRules`. Storage learnt from a
  rule, a group and a location created in the ePO 5.10 console; a policy
  built by the library (a group with a sub group, rules with networks,
  applications and schedule; console-made and Trellix rules changed, moved
  and removed) was imported, displayed as expected and exported back
  unchanged. The lengths are checked against the console fields (rule name
  100 characters...): ePO imports a longer rule name but the console then
  fails to open the policy. See `examples/firewall_rule_editing.py`.
- `examples/firewall_recon_detection.py`: adds network reconnaissance
  detection rules to an ENS Firewall Rules policy (MITRE ATT&CK T1046 /
  T1595.001): Block + "Treat match as intrusion" + Log rules at the end of the
  policy for the ports of the usual Windows Server, third-party and Linux
  services not already allowed, so that a port scan raises intrusion events
  in ePO without changing what the firewall blocks.
- Markdown export: the Exploit Prevention Exclusions table (console columns)
  and the details of each exclusion, instead of a count; the Executables
  column of the Application Protection Rules now shows the paths as the
  console does (`path;path;`).

**Fixed**
- ENS Firewall Rules: `load_policy()` crashed on an empty group (its sequence
  has no rule count); the schedule of the Markdown export and of
  `get_content()` showed Sunday when it wasn't selected (Sunday is the first
  bit of the WeekMask, not the last) and always 0:00 - 23:59 (the times are
  stored in ScheduleStart/End Hours/Minutes).
- `Policies.new_policy()`: a copy of an Exploit Prevention policy with
  exclusions kept their IDs, and the ePO console then failed to open the
  imported copy ("An unexpected error occurred."). The copy now gets new
  exclusion IDs.

**Security**
- Markdown export: policy, section, rule and subrule names written in headings
  are now escaped (new `Policy.md_heading()`), like the table cells already
  were. In 0.4.0 a name containing HTML (e.g. a rule named
  `<img src=x onerror=...>` by someone allowed to edit the policy in ePO)
  could be rendered as HTML by Markdown viewers that allow raw HTML.

### 0.4.0 - 2026-10-03

**Added**
- Markdown documentation of policies: `Policy.to_markdown()` /
  `save_markdown()` with Markdown helpers (`md_table`, `md_settings`...), for
  all ENS policy types; `examples/policy_documentation.py`.
- `ESTPPolicyAccessProtection` (ENS TP Access Protection) with an object model
  following the console workflow: `APRule`, `APSubRule`, `APTarget`,
  `APExecutable`, `APUserName` - rules are created, edited and removed
  (`add_rule()`, `update_rule()`, `remove_rule()`), exclusions too; checked end
  to end (built with the library, imported into ePO, shown as expected in the
  console, exported back unchanged); `examples/access_protection.py`.
  `ESTPPolicyOptions` (ENS TP Options: Quarantine Manager,
  Detection Exclusion, custom unwanted programs, Proactive Data Analysis) and
  `ESFWPolicyOptions` (ENS Firewall Options, including DNS Blocking, Defined
  Networks and Trusted Executables).
- `OASState` constants: the On-Access Scan "Disable and unregister with
  Windows Security Center" option (stored by ePO as `bOASEnabled` = 0 plus
  `bUnregisterWithWSC` = 1), supported by the `on_access_scan` property.

**Fixed**
- On-Demand Scan: the GTI sensitivity level getters/setters (`fs_`, `qs_`,
  `rs_gti_level`) looked for the setting in the wrong section (returned None,
  setter failed).
- ENS Firewall: `get_content()` crashed on ICMP rules without message type.
- Exploit Prevention: debug messages printed when loading a policy or applying
  a `SearchFilter`.

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
