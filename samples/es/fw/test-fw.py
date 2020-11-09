#!/usr/local/bin/python3

from mcafee_epo_policies import ESFWPolicyRules

ens_fw = ESFWPolicyRules()
ens_fw.load_from_file('fw_policy.xml')

assert ens_fw.get_epo_server() == 'W2012R2EPO51'
assert ens_fw.get_epo_version() == '5.9.1.0'

ens_fw.load_policy()
ens_fw.print_info()
ens_fw.print_sequences()

print('--End of execution.')