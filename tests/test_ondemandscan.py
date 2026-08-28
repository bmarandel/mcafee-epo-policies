"""
Ported from the user's own test-ods.py, run against a real ePO export
(ods_policy.xml) captured from a live ePO 5.10.0.0 server. The original
script only printed the locations/exclusions; the exact values observed
during this session's dry run are now asserted, so this test also protects
the fs_locations key template (szScanItem{row}, no underscore) touched by
the get_indexed_list/set_indexed_list refactor.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList

FIXTURE = Path(__file__).parent / 'fixtures' / 'ods_policy.xml'


@pytest.fixture
def ods_policy():
    policy = ESTPPolicyOnDemandScan()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_epo_metadata(ods_policy):
    assert ods_policy.get_epo_server() == 'W2K12R2EPO510'
    assert ods_policy.get_epo_version() == '5.10.0.0'


def test_fs_locations(ods_policy):
    locations = ods_policy.fs_locations
    assert locations == [
        'SpecialScanForRootkits', 'SpecialMemory', 'SpecialCritical', 'My Computer',
        'LocalDrives', 'All fixed disks', 'All removable media', 'All Network drives',
        'HomeDir', 'ProfileDir', 'WinDir', 'ProgramFilesDir', 'TempDir',
        'SpecialRecycleName', 'C:\\TestBen', 'D:\\Apps', 'SpecialRegistry',
    ]
    loc_list = ODSLocationList(locations)
    assert len(loc_list.loc_list) == 17


def test_fs_exclusion_list(ods_policy):
    exclusions = ods_policy.fs_exclusion_list
    assert exclusions == [['4', '0', 'LOG', '']]
    excl_list = ODSExclusionList(exclusions)
    assert len(excl_list.excl_list) == 1
    assert excl_list.contains_file_type('LOG') is True
