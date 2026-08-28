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

McAfee Agent policy coverage is complete - all 5 McAfee Agent policy types are implemented.

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

## Examples

The [`examples/`](examples/) directory has short, runnable scripts covering
McAfee Agent (General/Repository), ENS Threat Prevention (On-Access Scan,
On-Demand Scan), and ENS Firewall (Rules reporting).

## Documentation

There is no separate documentation site yet; every class and method has a
docstring describing which ePO UI setting it maps to.

## Requirements

Python 3.8 or later.

## Bugs and Feedback

For bugs, questions and discussions please use the [GitHub Issues](https://github.com/bmarandel/mcafee-epo-policies/issues).

## License

Copyright 2020 Benjamin Marandel

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License. 
