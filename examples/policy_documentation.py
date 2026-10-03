#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
policy_documentation.py

Example for the mcafee_epo_policies package: write one Markdown document per
policy of an ENS export (Threat Prevention or Firewall), to keep a
documentation of the enforced security policies (audits, compliance).

Each document has a metadata header, a table of contents, one section per
console tab and a document control section (review/approval sign-off and
change history) to fill in.

Usage:
    python3 policy_documentation.py <export.xml> [output_dir] [author]
"""

import os
import re
import sys

from mcafee_epo_policies import (ESTPPolicies, ESFWPolicies, ESTPPolicyOnAccessScan,
                                 ESTPPolicyOnDemandScan, ESTPPolicyExploitPrevention,
                                 ESTPPolicyOptions, ESTPPolicyAccessProtection, ESFWPolicyRules,
                                 ESFWPolicyOptions)

# Policy types with a Markdown export, per product of the export.
PRODUCTS = {
    'ENDP_AM_1000': (ESTPPolicies, {
        'EAM_General_Policies': ESTPPolicyOnAccessScan,
        'EAM_OnDemandScan_Policies': ESTPPolicyOnDemandScan,
        'EAM_BufferOverflow_Policies': ESTPPolicyExploitPrevention,
        'EAM_CommonScan_Policies': ESTPPolicyOptions,
        'EAM_BehaviorBlock_Policies': ESTPPolicyAccessProtection}),
    'ENDP_FW_META_FW': (ESFWPolicies, {
        'FireCore_FW_Rules': ESFWPolicyRules,
        'FW_StatusMode': ESFWPolicyOptions}),
}


def main():
    if len(sys.argv) not in (2, 3, 4):
        print('Usage: python3 policy_documentation.py <export.xml> [output_dir] [author]',
              file=sys.stderr)
        return 1
    output_dir = sys.argv[2] if len(sys.argv) >= 3 else '.'
    author = sys.argv[3] if len(sys.argv) == 4 else ''
    os.makedirs(output_dir, exist_ok=True)

    with open(sys.argv[1], 'rb') as export_file:
        xml_data = export_file.read()
    product = re.search(rb'featureid="([^"]+)"', xml_data)
    product = product.group(1).decode() if product else ''
    if product not in PRODUCTS:
        print('Unsupported product "{}": use an ENS Threat Prevention or Firewall export.'
              .format(product), file=sys.stderr)
        return 1
    container, classes = PRODUCTS[product]
    policies = container(xml_data)

    for item in policies.list():
        policy_class = classes.get(item['typeid'])
        if policy_class is None:
            print('Skipped (no Markdown export yet): {} - {}'.format(item['typeid'],
                                                                      item['name']))
            continue
        policy = policy_class(policies.get_policy(item['typeid'], item['name']))
        # e.g. "ENS Firewall - Options - My Default.md" (both TP and FW have Options).
        file_name = '{} - {} - {}.md'.format(
            policy.MD_PRODUCT.replace('Endpoint Security', 'ENS'), policy.MD_CATEGORY,
            re.sub(r'[\\/:*?"<>|]', '_', item['name']))
        policy.save_markdown(os.path.join(output_dir, file_name), author=author)
        print('Written: {}'.format(file_name))
    return 0


if __name__ == '__main__':
    sys.exit(main())
