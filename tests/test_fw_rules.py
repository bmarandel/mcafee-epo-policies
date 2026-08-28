"""
Ported from the user's own test-fw.py, run against a real ePO export
(fw_policy_all.xml) captured from a live ePO server. The original script only
printed the parsed policy; the exact counts/content observed during this
session's dry run are now asserted.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESFWPolicyRules

FIXTURE = Path(__file__).parent / 'fixtures' / 'fw_policy_all.xml'


@pytest.fixture
def fw_policy():
    policy = ESFWPolicyRules()
    policy.load_from_file(str(FIXTURE))
    policy.load_policy()
    return policy


def test_load_policy_counts(fw_policy):
    assert fw_policy.get_name() == 'Demo'
    assert len(fw_policy.seq) == 11
    assert len(fw_policy.rul) == 66
    assert len(fw_policy.agg) == 48


def test_get_content(fw_policy):
    content = fw_policy.get_content()
    assert content.startswith('# McAfee core networking/')
    assert 'Allow outbound System application' in content
    assert 'Action: ALLOW' in content
