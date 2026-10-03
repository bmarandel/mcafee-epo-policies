"""
ENS Threat Prevention Options, against tp_options.xml: a copy of "My Default"
from the lab ePO 5.10 with one Detection Exclusion ("EICAR test file") and one
user-defined unwanted program ("claudetest.exe") added in the console, to
learn how those rows are stored.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESTPPolicyOptions

FIXTURE = Path(__file__).parent / 'fixtures' / 'tp_options.xml'


@pytest.fixture
def options_policy():
    policy = ESTPPolicyOptions()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_read(options_policy):
    assert options_policy.get_name() == 'Claude - TP Options Test'
    assert options_policy.quarantine_folder == '<SYSTEM_DRIVE>\\Quarantine'
    assert options_policy.quarantine_age == 30
    assert options_policy.detection_exclusions == [['EICAR test file', 'Claude test exclusion']]
    assert options_policy.overwrite_detection_exclusions == '0'
    assert options_policy.pup_detections == [['claudetest.exe', 'Claude test PUP']]
    assert options_policy.gti_feedback == '1'
    assert options_policy.safety_pulse == '1'
    assert options_policy.amcore_reputation == '1'


def test_write(options_policy):
    options_policy.detection_exclusions = [['EICAR test file', ''], ['0123456789abcdef', 'hash']]
    options_policy.pup_detections = [['a.exe', 'Tool: A'], ['b.exe', '']]
    options_policy.quarantine_age = 60
    assert options_policy.detection_exclusions == [['EICAR test file', ''],
                                                   ['0123456789abcdef', 'hash']]
    assert options_policy.pup_detections == [['a.exe', 'Tool: A'], ['b.exe', '']]
    assert options_policy.get_setting_value('DetectionItems', 'UserDefinedDetection_0') == \
        'a.exe:Tool: A'
    assert options_policy.get_setting_value('SpyExclItems', 'dwSpywareExclCount') == '2'
    assert options_policy.quarantine_age == 60


def test_markdown(options_policy):
    text = options_policy.to_markdown()
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Quarantine Manager (Windows & Linux only)',
                        '## 2. Detection Exclusion (Windows only)',
                        '## 3. Potentially Unwanted Program Detections (Windows only)',
                        '## 4. Proactive Data Analysis (Windows & Linux only)',
                        '## 5. Document control']
    assert '| Quarantine folder | &lt;SYSTEM\\_DRIVE&gt;\\\\Quarantine |' in text
    assert '| Specify the maximum number of days to keep quarantine data (Windows only) | ' \
        'Yes (30 days) |' in text
    assert '| 1 | EICAR test file | Claude test exclusion |' in text
    assert '| 1 | claudetest.exe | Claude test PUP |' in text
    assert '| Check AMCore Content before installation: AMCore Content Reputation ' \
        '(Windows only) | Yes |' in text
