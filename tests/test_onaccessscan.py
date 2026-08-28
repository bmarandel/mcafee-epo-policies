"""
Ported from the user's own test-oas.py, run against oas_policy.xml - now the
most recent ENS Threat Prevention On-Access Scan export (ePO 5.10.0.0),
which also introduced the "Ransomware" options (detect_unknown_ransomware,
ransomware_bait_files).
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESTPPolicyOnAccessScan, OASProcessList, OASExclusionList

FIXTURE = Path(__file__).parent / 'fixtures' / 'oas_policy.xml'


@pytest.fixture
def oas_policy():
    policy = ESTPPolicyOnAccessScan()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_epo_metadata(oas_policy):
    assert oas_policy.get_epo_server() == 'W2022EPO510'
    assert oas_policy.get_epo_version() == '5.10.0.0'


def test_gti_level(oas_policy):
    assert oas_policy.get_gti_level() == '5'


def test_ransomware_options(oas_policy):
    # Detect unknown ransomware based on behaviour - checked by default.
    assert oas_policy.detect_unknown_ransomware == '1'
    oas_policy.detect_unknown_ransomware = '0'
    assert oas_policy.detect_unknown_ransomware == '0'

    # Create ransomware bait files on file system - unchecked by default.
    assert oas_policy.ransomware_bait_files == '0'
    oas_policy.ransomware_bait_files = '1'
    assert oas_policy.ransomware_bait_files == '1'


def test_process_list_workflow(oas_policy):
    proc_list = OASProcessList(oas_policy.get_process_list())

    proc_list.add('test.exe', 'Low Risk')
    assert proc_list.add('test.exe', 'High Risk') is False
    proc_list.add_low_risk('test_low.exe')
    proc_list.add_high_risk('test_high.exe')
    assert proc_list.contains('test.exe') is True
    assert proc_list.contains_low_risk('test_low.exe') is True
    assert proc_list.contains_high_risk('test_high.exe') is True

    proc_list.remove('test.exe')
    assert proc_list.contains('test.exe') is False


def test_exclusion_list_workflow(oas_policy):
    excl_list = OASExclusionList(oas_policy.get_exclusion_list())

    excl_list.add_folder('C:\\Test\\Folder\\', True, True, True, 'Test folder to remove')
    assert excl_list.contains_folder('C:\\Test\\Folder\\') is True
    assert excl_list.remove_folder('C:\\Test\\Folder\\') is True
    assert excl_list.contains_folder('C:\\Test\\Folder\\') is False

    excl_list.add_file_name('C:\\Test\\test.ben', True, True, 'Test file to remove')
    assert excl_list.contains_file_name('C:\\Test\\test.ben') is True
    assert excl_list.remove_file_name('C:\\Test\\test.ben') is True
    assert excl_list.contains_file_name('C:\\Test\\test.ben') is False

    excl_list.add_file_type('TEST', True, True, 'TEST extension to remove')
    assert excl_list.contains_file_type('TEST') is True
    assert excl_list.remove_file_type('TEST') is True
    assert excl_list.contains_file_type('TEST') is False

    excl_list.add_file_created(10, True, True, 'Created 10 days ago to remove')
    assert excl_list.contains_file_created(10) is True
    assert excl_list.remove_file_created(10) is True
    assert excl_list.contains_file_created(10) is False

    excl_list.add_file_modified(20, True, True, 'Modified 20 days ago to remove')
    assert excl_list.contains_file_modified(20) is True
    assert excl_list.remove_file_modified(20) is True
    assert excl_list.contains_file_modified(20) is False
