#!/usr/local/bin/python3

from mcafee_epo_policies import ESTPPolicyOnAccessScan, ProcessList, ExclusionList

ens_oas = ESTPPolicyOnAccessScan()
ens_oas.load_from_file('oas_policy.xml')

assert ens_oas.get_epo_server() == 'TESTSRV'
assert ens_oas.get_epo_version() == '5.9.1.0'

assert ens_oas.get_gti_level() == '0'

print('Process List:')
proc_list = ProcessList(ens_oas.get_process_list())

proc_list.add('test.exe', 'Low Risk')
assert proc_list.add('test.exe', 'High Risk') == False
proc_list.add_low_risk('test_low.exe')
proc_list.add_high_risk('test_high.exe')
assert proc_list.contains('test.exe') == True
assert proc_list.contains_low_risk('test_low.exe') == True
assert proc_list.contains_high_risk('test_high.exe') == True

proc_list.remove('test.exe')
assert proc_list.contains('test.exe') == False

print(repr(proc_list))
print(proc_list)

print('\nStandard Exclusions:')
excl_list = ExclusionList(ens_oas.get_exclusion_list())

excl_list.add_folder('C:\\Test\\Folder\\', True, True, True, 'Test folder to remove')
assert excl_list.contains_folder('C:\\Test\\Folder\\') == True
assert excl_list.remove_folder('C:\\Test\\Folder\\') == True
assert excl_list.contains_folder('C:\\Test\\Folder\\') == False

excl_list.add_file_name('C:\\Test\\test.ben', True, True, 'Test file to remove')
assert excl_list.contains_file_name('C:\\Test\\test.ben') == True
assert excl_list.remove_file_name('C:\\Test\\test.ben') == True
assert excl_list.contains_file_name('C:\\Test\\test.ben') == False

excl_list.add_file_type('TEST', True, True, 'TEST extension to remove')
assert excl_list.contains_file_type('TEST') == True
assert excl_list.remove_file_type('TEST') == True
assert excl_list.contains_file_type('TEST') == False

excl_list.add_file_created(10, True, True, 'Created 10 days ago to remove')
assert excl_list.contains_file_created(10) == True
assert excl_list.remove_file_created(10) == True
assert excl_list.contains_file_created(10) == False

excl_list.add_file_modified(20, True, True, 'Modified 20 days ago to remove')
assert excl_list.contains_file_modified(20) == True
assert excl_list.remove_file_modified(20) == True
assert excl_list.contains_file_modified(20) == False

excl_list.add_folder('C:\\Test\\Folder1\\', True, True, True, '01-Folder full with sub.')
excl_list.add_folder('C:\\Test\\Folder2\\', True, True, False, '02-Folder full without sub.')
excl_list.add_folder('C:\\Test\\Folder3\\', True, False, True, '03-Folder write with sub.')
excl_list.add_folder('C:\\Test\\Folder4\\', False, True, True, '04-Folder read with sub.')

excl_list.add_file_name('C:\\Test\\*.001', True, True, '05-File full')
excl_list.add_file_name('C:\\Test\\*.002', True, False, '06-File write only')
excl_list.add_file_name('C:\\Test\\*.003', False, True, '07-File read only')

excl_list.add_file_type('BE?', True, True, '08-Extension BE? full')
excl_list.add_file_type('BEN1', True, False, '09-Extension BEN1 write')
excl_list.add_file_type('BEN2', False, True, '10-Extension BEN2 read')

excl_list.add_file_created(10, True, True, '11-Created 10 days full')
excl_list.add_file_created(11, True, False, '12-Created 11 days write')
excl_list.add_file_created(12, False, True, '13-Created 12 days read')

excl_list.add_file_modified(20, True, True, '14-Modified 20 days full')
excl_list.add_file_modified(21, True, False, '15-Modified 21 days write')
excl_list.add_file_modified(22, False, True, '16-Modified 22 days read')

print(repr(excl_list))
print(excl_list)

print('\n--End of execution.')
