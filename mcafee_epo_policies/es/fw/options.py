# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESFWPolicyOptions.
"""

import xml.etree.ElementTree as et
from ...policies import Policy

class ESFWPolicyOptions(Policy):
    """
    The ESFWPolicyOptions class can be used to edit the Endpoint Security
    Firewall policy: Options. The setting names are the ones of the ePO 5.10
    console form fields; lists are stored as "_Name" (count) plus "+Name#row".
    """

    MD_PRODUCT = 'Endpoint Security Firewall'
    MD_CATEGORY = 'Options'

    # Trellix GTI network-reputation thresholds and "not reachable" action.
    GTI_THRESHOLDS = {'-100': 'Do not block', '50': 'High Risk', '30': 'Medium Risk',
                      '15': 'Unverified'}
    GTI_CONNECTIVITY = {'0': 'Block traffic', '1': 'Allow traffic unless specifically blocked by rules'}
    # Defined Networks address types.
    ADDRESS_TYPES = {'SingleIP': 'Single IP address', 'Subnet': 'Subnet',
                     'LocalSubnet': 'Local subnet', 'Range': 'Range',
                     'FQDN': 'Fully qualified domain name', 'AnyIPv4': 'Any IPv4 address',
                     'AnyIPv6': 'Any IPv6 address', 'AnyLocalIP': 'Any local IP address'}

    # Checkbox settings: (setting name, console label).
    __CHECKBOXES = {
        'FWStatus': 'Enable Firewall',
        'AllowUnknownProtocol': 'Allow traffic for unsupported protocols',
        'BootFw': 'Allow only outgoing traffic until firewall services have started',
        'AllowBridgedVmTraffic': 'Allow bridged traffic',
        'AllowIntrusionAlerts': 'Enable firewall intrusion alerts',
        'AdaptiveModeStatus': 'Enable Adaptive mode (creates rules on the client automatically)',
        'FactoryRulesDisableStatus': 'Disable Trellix core networking rules (Windows only)',
        'MergeRules': 'Retain existing user-added rules and Adaptive mode rules when this '
                      'policy is enforced',
        'LogAllBlocked': 'Log all blocked traffic (Windows & Linux only)',
        'LogAllAllowed': 'Log all allowed traffic (Windows & Linux only)',
        'GTIIntrusion': 'Treat Trellix GTI match as intrusion',
        'GTIEventStatus': 'Log matching traffic',
        'BlockAllUntrusted': 'Block all untrusted executables (Windows only)',
        'UntrustedExecutableObserveMode': 'Enable Observe mode',
        'InspectFTP': 'Use FTP protocol inspection',
        'AllowDisableFirewall': 'Allow users to disable Firewall from the Trellix system '
                                'tray icon',
        'RetainFirewallStatus': 'Retain user-disabled Firewall status when this policy is '
                                'enforced',
        'MandateUserComments': 'Require justification from users when managing Firewall from '
                               'the Trellix system tray icon',
    }

    def __init__(self, policy_from_esfwpolicies=None):
        super(ESFWPolicyOptions, self).__init__(policy_from_esfwpolicies)
        if policy_from_esfwpolicies is not None:
            if self.get_type() != 'FW_StatusMode':
                raise ValueError('Wrong policy! Policy type must be "FW_StatusMode".')

    def __repr__(self):
        return 'ESFWPolicyOptions()'

    def __section(self):
        """
        Returns the Section holding the settings (its name is the policy
        settings "param_str", e.g. "8").
        """
        return self.root.find('./EPOPolicySettings/Section')

    def get_option(self, setting):
        """
        Get the value of an option, e.g. get_option('FWStatus'). The setting
        names are the keys of ESFWPolicyOptions.options().
        """
        setting_obj = self.__section().find('Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_option(self, setting, value):
        """
        Set the value of an existing option, e.g. set_option('FWStatus', '0').
        """
        setting_obj = self.__section().find('Setting[@name="{}"]'.format(setting))
        if setting_obj is None:
            return False
        setting_obj.set('value', str(value))
        return True

    @classmethod
    def options(cls):
        """
        Returns the checkbox options as a dict {setting name: console label}.
        """
        return dict(cls.__CHECKBOXES)

    def __get_list(self, name):
        section = self.__section()
        count = section.find('Setting[@name="_{}"]'.format(name))
        values = []
        for row in range(int(count.get('value')) if count is not None else 0):
            setting_obj = section.find('Setting[@name="+{}#{}"]'.format(name, row))
            values.append(setting_obj.get('value') if setting_obj is not None else '')
        return values

    def __set_list(self, name, values):
        section = self.__section()
        for setting_obj in section.findall('Setting'):
            if setting_obj.get('name') == '_' + name or \
                    setting_obj.get('name').startswith('+{}#'.format(name)):
                section.remove(setting_obj)
        et.SubElement(section, 'Setting', {'name': '_' + name, 'value': str(len(values))})
        for row, value in enumerate(values):
            et.SubElement(section, 'Setting', {'name': '+{}#{}'.format(name, row),
                                               'value': value})
        return True

    # ------------------------------ Options Policy ------------------------------
    # Firewall: Enable Firewall
    def get_firewall(self):
        """
        Get the Enable Firewall state
        """
        return self.get_option('FWStatus')

    def set_firewall(self, mode):
        """
        Set the Enable Firewall state
        """
        return self.set_option('FWStatus', mode)

    firewall = property(get_firewall, set_firewall)

    # Trellix GTI Network Reputation (Windows only): thresholds ('-100' Do not
    # block, '50' High Risk, '30' Medium Risk, '15' Unverified).
    def get_gti_incoming_threshold(self):
        """
        Get the Incoming network-reputation threshold
        """
        return self.get_option('GTIIn')

    def set_gti_incoming_threshold(self, value):
        """
        Set the Incoming network-reputation threshold ('-100', '50', '30' or '15')
        """
        if value not in self.GTI_THRESHOLDS:
            raise ValueError('Threshold must be within {}.'.format(list(self.GTI_THRESHOLDS)))
        return self.set_option('GTIIn', value)

    gti_incoming_threshold = property(get_gti_incoming_threshold, set_gti_incoming_threshold)

    def get_gti_outgoing_threshold(self):
        """
        Get the Outgoing network-reputation threshold
        """
        return self.get_option('GTIOut')

    def set_gti_outgoing_threshold(self, value):
        """
        Set the Outgoing network-reputation threshold ('-100', '50', '30' or '15')
        """
        if value not in self.GTI_THRESHOLDS:
            raise ValueError('Threshold must be within {}.'.format(list(self.GTI_THRESHOLDS)))
        return self.set_option('GTIOut', value)

    gti_outgoing_threshold = property(get_gti_outgoing_threshold, set_gti_outgoing_threshold)

    # Stateful Firewall: time-outs (Windows & Mac only)
    def get_tcp_timeout(self):
        """
        Get the Number of seconds (1-240) before TCP connections time out
        """
        return int(self.get_option('TCPTimeout'))

    def set_tcp_timeout(self, int_seconds):
        """
        Set the Number of seconds (1-240) before TCP connections time out
        """
        if int_seconds < 1 or int_seconds > 240:
            raise ValueError('The TCP time-out must be within 1-240 seconds.')
        return self.set_option('TCPTimeout', int_seconds)

    tcp_timeout = property(get_tcp_timeout, set_tcp_timeout)

    def get_udp_icmp_timeout(self):
        """
        Get the Number of seconds (1-300) before UDP and ICMP echo virtual
        connections time out
        """
        return int(self.get_option('VCTimeout'))

    def set_udp_icmp_timeout(self, int_seconds):
        """
        Set the Number of seconds (1-300) before UDP and ICMP echo virtual
        connections time out
        """
        if int_seconds < 1 or int_seconds > 300:
            raise ValueError('The UDP/ICMP time-out must be within 1-300 seconds.')
        return self.set_option('VCTimeout', int_seconds)

    udp_icmp_timeout = property(get_udp_icmp_timeout, set_udp_icmp_timeout)

    # DNS Blocking: Domain name (can include wildcards: *.domain.com)
    def get_blocked_domains(self):
        """
        Get the DNS Blocking domain names (list of strings)
        """
        return self.__get_list('BlockedDomains')

    def set_blocked_domains(self, domains):
        """
        Set the DNS Blocking domain names (list of strings)
        """
        return self.__set_list('BlockedDomains', domains)

    blocked_domains = property(get_blocked_domains, set_blocked_domains)

    # Defined Networks: Address type, Address, Trusted/Not trusted
    def get_defined_networks(self):
        """
        Get the Defined Networks: a list of dicts {'type', 'address', 'trusted'}
        (type: see ESFWPolicyOptions.ADDRESS_TYPES; trusted: '1' or '0').
        """
        return [{'type': typ, 'address': address, 'trusted': trusted}
                for typ, address, trusted in zip(self.__get_list('AddressType'),
                                                 self.__get_list('AddressValue'),
                                                 self.__get_list('IsTrusted'))]

    def set_defined_networks(self, networks):
        """
        Set the Defined Networks from a list of dicts {'type', 'address', 'trusted'}.
        """
        for network in networks:
            if network['type'] not in self.ADDRESS_TYPES:
                raise ValueError('Address type must be within {}.'.format(
                    list(self.ADDRESS_TYPES)))
        self.__set_list('AddressType', [network['type'] for network in networks])
        self.__set_list('AddressValue', [network['address'] for network in networks])
        return self.__set_list('IsTrusted', [network['trusted'] for network in networks])

    defined_networks = property(get_defined_networks, set_defined_networks)

    # Trusted Executables (Windows only): Name, File Name or Path, File
    # Description, MD5 Hash, Signature, Note
    __EXE_FIELDS = [('name', 'TrustedExeName'), ('path', 'TrustedExePath'),
                    ('description', 'TrustedExeDesc'), ('hash', 'TrustedExeHash'),
                    ('signature', 'TrustedExeSignature'), ('note', 'TrustedExeNote')]

    def get_trusted_executables(self):
        """
        Get the Trusted Executables: a list of dicts {'name', 'path',
        'description', 'hash', 'signature', 'note'}.
        """
        columns = [self.__get_list(setting) for _, setting in self.__EXE_FIELDS]
        return [dict(zip([key for key, _ in self.__EXE_FIELDS], row)) for row in zip(*columns)]

    def set_trusted_executables(self, executables):
        """
        Set the Trusted Executables from a list of dicts {'name', 'path',
        'description', 'hash', 'signature', 'note'} (missing keys are empty).
        """
        for key, setting in self.__EXE_FIELDS:
            self.__set_list(setting, [executable.get(key, '') for executable in executables])
        return True

    trusted_executables = property(get_trusted_executables, set_trusted_executables)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        row = lambda setting: [self.__CHECKBOXES[setting], self.md_check(self.get_option(setting))]
        sections = [('Firewall', self.md_settings([row('FWStatus')]))]
        sections.append(('Protection Options (Windows only)', self.md_settings(
            [row(setting) for setting in ['AllowUnknownProtocol', 'BootFw',
                                          'AllowBridgedVmTraffic', 'AllowIntrusionAlerts']])))
        sections.append(('Tuning Options', self.md_settings(
            [row(setting) for setting in ['AdaptiveModeStatus', 'FactoryRulesDisableStatus',
                                          'MergeRules', 'LogAllBlocked', 'LogAllAllowed']])))
        rows = [row('GTIIntrusion'), row('GTIEventStatus'), row('BlockAllUntrusted')]
        if self.get_option('BlockAllUntrusted') == '1':
            rows.append(row('UntrustedExecutableObserveMode'))
        rows += [['Incoming network-reputation threshold',
                  self.GTI_THRESHOLDS.get(self.get_option('GTIIn'), self.get_option('GTIIn'))],
                 ['Outgoing network-reputation threshold',
                  self.GTI_THRESHOLDS.get(self.get_option('GTIOut'), self.get_option('GTIOut'))],
                 ['If Trellix GTI ratings server is not reachable',
                  self.GTI_CONNECTIVITY.get(self.get_option('GTIConnectivity'),
                                            self.get_option('GTIConnectivity'))]]
        sections.append(('Trellix GTI Network Reputation (Windows only)', self.md_settings(rows)))
        sections.append(('Stateful Firewall', self.md_settings([
            row('InspectFTP'),
            ['Number of seconds (1-240) before TCP connections time out (Windows & Mac only)',
             self.get_option('TCPTimeout')],
            ['Number of seconds (1-300) before UDP and ICMP echo virtual connections time out '
             '(Windows & Mac only)', self.get_option('VCTimeout')]])))
        rows = [row('AllowDisableFirewall')]
        if self.get_option('AllowDisableFirewall') == '1':
            rows.append(row('RetainFirewallStatus'))
        rows.append(row('MandateUserComments'))
        sections.append(('Firewall Status Control', self.md_settings(rows)))
        sections.append(('DNS Blocking', self.md_table(
            ['Domain name'], [[domain] for domain in self.get_blocked_domains()], numbered=True)))
        sections.append(('Defined Networks', self.md_table(
            ['Address type', 'Address', 'Trusted'],
            [[self.ADDRESS_TYPES.get(network['type'], network['type']), network['address'],
              'Trusted' if network['trusted'] == '1' else 'Not trusted']
             for network in self.get_defined_networks()], numbered=True)))
        sections.append(('Trusted Executables (Windows only)', self.md_table(
            ['Name', 'File Name or Path', 'File Description', 'MD5 Hash', 'Signature', 'Note'],
            [[exe['name'], exe['path'], exe['description'], exe['hash'], exe['signature'],
              exe['note']] for exe in self.get_trusted_executables()], numbered=True)))
        return sections
