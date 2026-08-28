#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
firewall_rules.py

Example for the mcafee_epo_policies package: load an ENS Firewall Rules
policy and export its rule tree as a Markdown report.

Note: ESFWPolicyRules is currently read-only/reporting - there is no
supported way yet to edit firewall rules through this library.

Usage:
    python3 firewall_rules.py <policy.xml> [output.md]
"""

import sys

from mcafee_epo_policies import ESFWPolicyRules


def main():
    if len(sys.argv) not in (2, 3):
        print('Usage: python3 firewall_rules.py <policy.xml> [output.md]', file=sys.stderr)
        return 1

    policy = ESFWPolicyRules()
    policy.load_from_file(sys.argv[1])
    policy.load_policy()
    policy.print_info()

    output_path = sys.argv[2] if len(sys.argv) == 3 else 'firewall_rules.md'
    with open(output_path, 'w') as report_file:
        report_file.write(policy.get_content())
    print('Report written to {}'.format(output_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
