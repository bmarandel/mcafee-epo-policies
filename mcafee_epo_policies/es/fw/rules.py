# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2020 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESFWPolicyRules.
"""

import datetime as dt
import ipaddress as ip
import xml.etree.ElementTree as et
from .protocols import InternetProtocols, MessageTypes, MessageTypesv6, NetworkProtocols
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
            policy_set = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_ref.text))
            set_type = int(policy_set.get('param_int'))
            if set_type == 100:
                self.__load_sequence(policy_set)
            elif set_type == 101:
                self.__load_rule(policy_set)
            elif set_type == 104:
                self.__load_aggreagate(policy_set)
            else:
                raise ValueError('Unknown param_int value int policy:{}'.format(set_type))
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

    def get_sequences(self, seq_id = 'root'):
        """
        DRAFT - Return all the rules within a global Json dictionary.
        """
        if seq_id == 'root':
            item = dict()
            item['Action'] = 'ROOT'
            children = list()
            for seq in self.seq[seq_id]:
                children.append(self.get_sequences(seq))
            item['Children'] = children
        else:
            item = self.rul[seq_id]
            # Does this rule contains Aggregate references, if so proceed in consequence
            agg_ref = item.get('AggRef', None)
            if agg_ref is not None:
                aggregates = list()
                for ref in agg_ref:
                    aggregates.append(self.agg[ref])
                item['AggRef'] = aggregates
            # If this sequence contains other sequences so proceeed in consequence
            if self.seq.__contains__(seq_id):
                children = list()
                for seq in self.seq[seq_id]:
                    children.append(self.get_sequences(seq))
                item['Children'] = children
        return item

    def get_toc(self, seq_id = 'root', level = 0, header = ''):
        """
        DRAFT - Return the table of content in Markdown format.
        """
        toc = ''
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            rul = self.rul[seq]
            toc += '{}- [{}](#{})'.format(header, rul['Name'], rul['GUID'])
            if rul['Action'] == "JUMP":
                toc += '/'
            toc += '\r\n'
            if self.seq.__contains__(seq):
                toc += self.get_toc(seq, level+1, header+'  ')
        return toc

    def __get_connection_type(self, rul_seq):
        intf = self.rul[rul_seq].get('PhysicalMedium', 'All')
        if intf != 'All':
            if len(intf) == 3:
                intf = 'All'
            elif len(intf) == 2:
                intf = ' or '.join(intf)
            else:
                intf = intf[0]
        if intf == 'All':
            intf = 'All types (Wired, Wireless, Virtual)'
        return intf

    def __get_last_changed(self, rul_seq):
        txt = 'By ' + self.rul[rul_seq]['LastModifyingUsername'] + ' on '
        dt_str = self.rul[rul_seq]['LastModified']
        dt_obj = dt.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f%z')
        txt += dt_obj.strftime('%Y/%m/%d at %H:%M:%S %Z.')
        return txt

    def __get_protocol(self, rul_seq):
        # TransportProtocol (example: '6')
        #   Users can select only one TransportProtocol
        tp = self.rul[rul_seq].get('TransportProtocol', 'All Protocols')
        if not tp == 'All Protocols':
            ips = InternetProtocols()
            tp = ips.get_name(tp[0])

        # NetworkProtocol (example: '2048', '34525')
        #   Users can select only one NetworkProtocol
        #   except for IPv4 and IPv6
        np = self.rul[rul_seq].get('NetworkProtocol', 'Any')
        if not np == 'Any':
            nps = NetworkProtocols()
            txt = tp + '/' + nps.get_name(np[0])
            if len(np) == 2:
                txt += ', ' + tp + '/' + nps.get_name(np[1])
        else:
            txt = tp + '/Any'

        # In case of ICMP or ICMPv6 MessageType is defined.
        #   The value is empty when All messages are defined.
        #   Users can select only one MessageType
        mt = self.rul[rul_seq].get('MessageType')
        if tp == 'ICMP' or tp == 'ICMPv6':
            txt += '\r\nMessage Type: '
            if mt[0] == '':
                txt += 'All'
            else:
                if tp == 'ICMP':
                    mts = MessageTypes()
                else:
                    mts = MessageTypesv6()
                txt += mts.get_name(mt[0])

        return txt

    def __get_ipaddress(self, str_ip):
        txt = str_ip
        if str_ip.isalnum():
            # This is a hostname
            pass
        elif len(str_ip.split('.')) > 1:
            # This is a domain
            pass
        elif str_ip == '[trusted]':
            # This is an internal object
            txt = 'Defined Networks (trusted)'
        elif len(str_ip.split('/')) > 1:
            # This is subnet
            ip1, sub = str_ip.split('/')
            ip1_addr = ip.ip_address(ip1)
            if ip1_addr.ipv4_mapped is not None:
                txt = str(ip1_addr.ipv4_mapped) + '/' + str(int(sub)-96)
        elif len(str_ip.split('-')) > 1:
            # This is a subnet range
            ip1, ip2 = str_ip.split('-')
            ip1_addr = ip.ip_address(ip1)
            ip2_addr = ip.ip_address(ip2)
            if ip1_addr.ipv4_mapped is not None:
                txt = str(ip1_addr.ipv4_mapped) + '-' + str(ip2_addr.ipv4_mapped)
        else:
            # This is a single ip
            ip_addr = ip.ip_address(str_ip)
            if ip_addr.ipv4_mapped is not None:
                txt = str(ip_addr.ipv4_mapped)
        return txt

    def __get_location(self, agg_ref):
        txt = ''
        agg = self.agg[agg_ref]
        txt = '  - Name: ' + agg['Name'] + '\r\n'
        txt += '  - Isolated: '
        txt += 'Yes\r\n' if agg['Isolated'] == '1' else 'No\r\n'
        txt += '  - Require ePO Reachability: '
        txt += 'Yes\r\n' if agg['RequireEpoReachable'] == '1' else 'No\r\n'
        # Print Default Gateway
        dgs = agg.get('DefaultGateway', None)
        if dgs is not None:
            txt += '  - Default Gateway:\r\n'
            for dg in dgs:
                txt += '    - ' + self.__get_ipaddress(dg) + '\r\n'
        # Print DHCP Server
        dss = agg.get('DhcpServer', None)
        if dss is not None:
            txt += '  - DHCP Server:\r\n'
            for ds in dss:
                txt += '    - ' + self.__get_ipaddress(ds) + '\r\n'
        # Print DNS Server
        dns = agg.get('DnsServer', None)
        if dns is not None:
            txt += '  - DNS Server:\r\n'
            for ds in dns:
                txt += '    - ' + self.__get_ipaddress(ds) + '\r\n'
        # Print DNS Suffix
        dsu = agg.get('DnsSuffix', None)
        if dsu is not None:
            txt += '  - DNS Suffix:\r\n'
            for ds in dsu:
                txt += '    - ' + ds + '\r\n'
        # Print Primary WINS Server
        pws = agg.get('PrimaryWINS', None)
        if pws is not None:
            txt += '  - Primary WINS Server:\r\n'
            for ds in pws:
                txt += '    - ' + self.__get_ipaddress(ds) + '\r\n'
        # Print Secondary WINS Server
        sws = agg.get('SecondaryWINS', None)
        if sws is not None:
            txt += '  - Secondary WINS Server:\r\n'
            for ds in sws:
                txt += '    - ' + self.__get_ipaddress(ds) + '\r\n'
        # Print Domain reachability (HTTPS)
        drs = agg.get('DomainReachable', None)
        if drs is not None:
            txt += '  - Domain reachability (HTTPS):\r\n'
            for ds in drs:
                txt += '    - ' + ds + '\r\n'
        # Print Registry Key/Value
        reg_key = agg.get('RegKey', None)
        if reg_key is not None:
            txt += '  - Registry Key: ' + reg_key[0] + '\r\n'
        return txt

    def __get_local_networks(self, agg_ref):
        txt = ''
        is_local = False
        if agg_ref is not None:
            tmp = ''
            for ref in agg_ref:
                obj = self.agg[ref]
                lns = obj.get('LocalAddress', None)
                if lns is not None:
                    is_local = True
                    tmp += '  - ' + obj['Name'] + ':\r\n'
                    for ln in lns:
                        tmp += '    - ' + self.__get_ipaddress(ln) + '\r\n'
        if is_local:
            txt = 'Local networks:\r\n' + tmp
        return txt

    def __get_local_port(self, seq):
        txt = ''
        lp = self.rul[seq].get('LocalPort', None)
        if lp is not None:
            txt += 'Local port: ' + lp[0] + '\r\n'
        return txt

    def __get_remote_networks(self, agg_ref):
        txt = ''
        is_remote = False
        if agg_ref is not None:
            tmp = ''
            for ref in agg_ref:
                obj = self.agg[ref]
                rns = obj.get('RemoteAddress', None)
                if rns is not None:
                    is_remote = True
                    tmp += '  - ' + obj['Name'] + ':\r\n'
                    for rn in rns:
                        tmp += '    - ' + self.__get_ipaddress(rn) + '\r\n'
        if is_remote:
            txt = 'Remote networks:\r\n' + tmp
        return txt

    def __get_remote_port(self, seq):
        txt = ''
        rp = self.rul[seq].get('RemotePort', None)
        if rp is not None:
            txt += 'Remote port: ' + rp[0] + '\r\n'
        return txt

    def __get_scheduled(self, seq):
        txt = ''
        # Does a schedule is defined?
        if self.rul[seq].get('ScheduleEnabled') == '1':
            # Print Scheduled status
            txt += 'Scheduled status: Enabled\r\n'
            # Print Scheduled days
            txt += 'Scheduled days: '
            days = int(self.rul[seq]['WeekMask'])
            ld = list()
            if (days - 2) >= 0:
                ld.append('Monday')
                days -= 2
            if (days - 4) >= 0:
                ld.append('Tuesday')
                days -= 4
            if (days - 8) >= 0:
                ld.append('Wednesday')
                days -= 8
            if (days - 16) >= 0:
                ld.append('Thursday')
                days -= 16
            if (days - 32) >=0:
                ld.append('Friday')
                days -= 32
            if (days - 64) >= 0:
                ld.append('Saturday')
                days -= 64
            if (days - 128) >= 0:
                ld.append('Sunday')
            txt += ', '.join(ld) + '\r\n'
            # Print Start time
            txt += 'Start time: ' + self.rul[seq]['StartTime'] + '\r\n'
            # Print End time
            txt += 'End time: ' + self.rul[seq]['EndTime'] + '\r\n'
        return txt

    def get_content(self, seq_id = 'root', level = 0, header = '', toc = False):
        """
        DRAFT - Get the content of a policy in Markdown format.
        """
        txt = ''
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            rul = self.rul[seq]
            # Print Title
            if toc:
                txt += '<div id="{}" />\r\n'.format(rul['GUID'])
            txt += '#' + '#'*level + ' '  #-- Heading is computed based on the level
            txt += rul['Name']

            # Is it a folder?
            if rul['Action'] == "JUMP":
                # This is a folder so print a slash at the end
                txt += '/\r\n\r\n'
            else:
                # This is a rule so print the rule settings
                txt += '\r\n\r\n'
                txt += 'Status: '
                txt += 'Enabled\r\n' if rul['Enabled'] == '1' else 'Disabled\r\n'
                txt += 'Action: ' + rul['Action'] + '\r\n'
                txt += 'Treat match as intrusion: '
                txt += 'Yes\r\n' if rul['Intrusion'] == '1' else 'No\r\n'
                txt += 'Log matching traffic: '
                txt += 'Yes\r\n' if rul['Logged'] == '1' else 'No\r\n'

            # Print the common section
            txt += 'Direction: ' + rul['Direction'] + '\r\n'
            txt += 'Connection type: ' + self.__get_connection_type(seq) + '\r\n'
            txt += 'Protocol: ' + self.__get_protocol(seq) + '\r\n'

            agg_ref = rul.get('AggRef', None)
            # Is it a folder?
            if rul['Action'] == "JUMP":
                # This is a folder so, check if a location is defined
                if agg_ref is not None:
                    # Print the location
                    txt += 'Location:\r\n' + self.__get_location(agg_ref[0])
            else:
                # This is a rule, continu to print settings
                # Print Local networks
                txt += self.__get_local_networks(agg_ref)
                # Print Local port
                txt += self.__get_local_port(seq)
                # Print Remote networks
                txt += self.__get_remote_networks(agg_ref)
                # Print Remote port
                txt += self.__get_remote_port(seq)
                # Is this rule a scheduled one
                txt += self.__get_scheduled(seq)

            # Print end of the common section
            txt += 'Note: ' + rul['Note'] + '\r\n'
            txt += 'Last Changed: ' + self.__get_last_changed(seq) + '\r\n'
            txt += '\r\n'

            #  Is there a child sequence under the current one ?
            if self.seq.__contains__(seq):
                # If yes, run recurcively the function to display all the children.
                txt += self.get_content(seq, level+1, header+'  ')
        return txt
