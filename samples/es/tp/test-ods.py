#!/usr/local/bin/python3

from mcafee_epo_policies import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList

ens_ods = ESTPPolicyOnDemandScan()
ens_ods.load_from_file('ods_policy.xml')

assert ens_ods.get_epo_server() == 'W2K12R2EPO510'
assert ens_ods.get_epo_version() == '5.10.0.0'

#assert ens_ods.get_fs_gti_level() == '3'

print('Full Scan - Locations:')
loc_list = ODSLocationList(ens_ods.fs_locations)

print(repr(loc_list))
print(loc_list)

print('\nFull Scan - Exclusions:')
excl_list = ODSExclusionList(ens_ods.fs_exclusion_list)
print(repr(excl_list))
print(excl_list)

print('\n--End of execution.')