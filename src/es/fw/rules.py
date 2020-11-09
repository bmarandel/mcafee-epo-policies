# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESFWPolicyRules.
"""

import xml.etree.ElementTree as et
from ...policies import Policy

class ESFWPolicyRules(Policy):
    """
    The ESFWPolicyRules class can be used to edit the Endpoint Security
    Firewall policy: Rules.
    """

    def __init__(self, policy_from_esfwpolicies=None):
        super(ESFWPolicyRules, self).__init__(policy_from_esfwpolicies)
        if policy_from_esfwpolicies is not None:
            if self.get_type() != 'FireCore_FW_Rules':
                raise ValueError('Wrong policy! Policy type must be "FireCore_FW_Rules".')
        self.seq = dict()
        self.rul = dict()
        self.agg = dict()

    def __repr__(self):
        return 'ESTPPolicyOnAccessScan()'

    def load_policy(self):
        policy_obj = self.root.find('EPOPolicyObject')
        for policy_ref in policy_obj.findall('PolicySettings'):
            #print(policy_ref.text)
            policy_set = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_ref.text))
            set_type = int(policy_set.get('param_int'))
            if set_type == 100:
                self.__load_sequence(policy_set)
            elif set_type == 101:
                self.__load_rule(policy_set)
            elif set_type == 104:
                self.__load_aggreagate(policy_set)
            else:
                print('Unknown value:{}'.format(set_type))
        return True

    def __load_sequence(self, policy_settings):
        # Enter in the sequence section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                           policy_settings.get('param_str')))
        # Determine the GUID of that sequence
        setting_obj = section_obj.find('Setting[@name="{}"]'.format('RuleListID'))
        # If the sequence has no value, it's the root sequence
        if setting_obj is not None:
            seq_key = setting_obj.get('value')
        else:
            seq_key = 'root'
        # Build the sequence list with respect of the order
        seq_list = list()
        max_rows = int(section_obj.find('Setting[@name="{}"]'.format(
                                        '_RuleIDSequence')).get('value'))
        for row in range(max_rows):
            seq_list.append(section_obj.find('Setting[@name="{}{}"]'.format(
                                             '+RuleIDSequence#', row)).get('value'))
        # Add the sequence ID with all sub sequences to the main dict
        self.seq[seq_key] = seq_list

    def __load_rule(self, policy_settings):
        # Enter in the rule section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                           policy_settings.get('param_str')))
        # Determine the GUID of that rule
        rul_key = section_obj.find('Setting[@name="{}"]'.format('GUID')).get('value')
        # Build the rule with all properties
        rul_props = dict()
        prop_keys = section_obj.findall('Setting')
        for prop in prop_keys:
            prop_key = prop.get('name')
            # If it's a simple property, get its value
            if prop_key[0] != "+" and prop_key[0] != "_":
                rul_props[prop_key] = prop.get('value')
            # If it's a list, get all possible values
            if prop_key[0] == "_":
                prop_val = list()
                max_rows = int(prop.get('value'))
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="+{}#{}"]'.format(
                                                    prop_key[1:], row))
                    prop_val.append(setting_obj.get('value'))
                rul_props[prop_key[1:]] = prop_val
        # Add the rule ID with all properties to the main dict
        self.rul[rul_key] = rul_props

    def __load_aggreagate(self, policy_settings):
        # Enter in the aggregate section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                            policy_settings.get('param_str')))
        # Determine the GUID of that aggregate
        agg_key = section_obj.find('Setting[@name="{}"]'.format('GUID')).get('value')
        # Build the aggregate with all properties
        agg_props = dict()
        prop_keys = section_obj.findall('Setting')
        for prop in prop_keys:
            prop_key = prop.get('name')
            # If it's a simple property, get its value
            if prop_key[0] != "+" and prop_key[0] != "_":
                agg_props[prop_key] = prop.get('value')
            # If it's a list, get all possible values
            if prop_key[0] == "_":
                prop_val = list()
                max_rows = int(prop.get('value'))
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="+{}#{}"]'.format(
                                                    prop_key[1:], row))
                    prop_val.append(setting_obj.get('value'))
                agg_props[prop_key[1:]] = prop_val
        # Add the rule ID with all properties to the main dict
        self.agg[agg_key] = agg_props

    def print_info(self):
        """
        Print information about the current loaded policy object.
        """
        print('Policy {} has {} sequences, {} rules and {} aggregates.'.format(
              self.get_name(), len(self.seq), len(self.rul), len(self.agg)))

    def print_sequences(self, seq_id = 'root', level = 0, header = ''):
        """
        DRAFT - Print the current firewall policy.
        """
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            intf = self.rul[seq].get('PhysicalMedium', 'All')
            if intf != 'All':
                if len(intf) == 3:
                    intf = 'All'
                else:
                    intf = ','.join(intf)
            if self.rul[seq]['Action'] == "JUMP":
                print('{}+-- {}/'.format(header, self.rul[seq]['Name']))
                agg_ref = self.rul[seq].get('AggRef', None)
                if agg_ref is not None:
                    agg_ref = agg_ref[0]
                    print('{}--> Name: {}, Direction: {}, Interfaces: {}'.format(header+'|   ',
                            self.agg[agg_ref]['Name'], self.rul[seq]['Direction'], intf))
            else:
                print('{}+-- {}'.format(header, self.rul[seq]['Name']))
                print('{}--> Action: {}, Direction: {}'.format(
                      header+'|   ', self.rul[seq]['Action'], self.rul[seq]['Direction']))
                print('{}--> Interfaces: {} Protocol: {}'.format(
                      header+'|   ', intf, self.rul[seq].get('TransportProtocol', 'Any')))
            if self.seq.__contains__(seq):
                self.print_sequences(seq, level+1, header+'|   ')
