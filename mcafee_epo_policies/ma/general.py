# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class McAfeeAgentPolicyGeneral.
"""

import xml.etree.ElementTree as et
from ..policies import Policy

class McAfeeAgentPolicyGeneral(Policy):
    """
    The McAfeeAgentPolicyGeneral class can be used to edit the McAfee Agent policy: General.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(McAfeeAgentPolicyGeneral, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'General':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "General".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<McAfeeAgentPolicyGeneral for policy {} from server {}.>'.format(name, epo)

    def get_table_value(self, section, keys):
        """
        Get a table (list of list) of a specific section in the XML content
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is not None:
            setting_obj = section_obj.find('Setting[@name="NumberOfItems"]')
            max_rows = int(setting_obj.get('value'))
            max_cols = len(keys)
            table = []
            for row in range(max_rows):
                row_value = {}
                for col in range(max_cols):
                    setting_obj = section_obj.find('Setting[@name="{}_{}"]'.format(keys[col], row))
                    row_value[keys[col]] = setting_obj.get('value')
                table.append(row_value)
        return table

    def set_table_value(self, section, table):
        """
        Set a table (list of list) of a specific section in the XML content
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is not None:
            success = True
            max_rows = len(table)
            keys = table[0].keys()
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name=section)
            et.SubElement(section_obj, 'Setting', {"name":'NumberOfItems', "value":str(max_rows)})
            for row in range(max_rows):
                for key in keys:
                    et.SubElement(section_obj,
                                  'Setting',
                                  {"name":'{}_{}'.format(key, row), "value":table[row][key]})
        return success

    # ------------------------------ GENERAL TAB ------------------------------
    # General options:
    #   Policy enforcement interval (minutes)
    def get_policy_enforcement_interval(self):
        """
        Get Policy enforcement interval (minutes)
        """
        value = self.get_setting_value('PolicyService', 'PolicyEnforcementTimeout')
        return int(value) if value is not None else int(
            self.get_setting_value('General', 'PolicyEnforcementInterval'))/60

    def set_policy_enforcement_interval(self, int_minutes):
        """
        Set Policy enforcement interval (minutes)
        """
        if int_minutes < 5:
            raise ValueError('Interval below 5 minutes is not possible.')
        self.set_setting_value('PolicyService', 'PolicyEnforcementTimeout', str(int_minutes), True)
        return self.set_setting_value('General', 'PolicyEnforcementInterval', str(int_minutes*60))

    policy_enforcement_interval = property(get_policy_enforcement_interval,
                                           set_policy_enforcement_interval)

    #   Show the McAfee system tray icon (Windows only)
    def get_mcafee_system_tray_icon(self):
        """
        Get state of Show the McAfee system tray icon (Windows only)
        """
        return self.get_setting_value('General', 'ShowAgentUI')

    def set_mcafee_system_tray_icon(self, mode):
        """
        Set state of Show the McAfee system tray icon (Windows only)
        """
        self.set_setting_value('UpdaterService', 'EnableAgentUI', mode)
        return self.set_setting_value('General', 'ShowAgentUI', mode)

    mcafee_system_tray_icon = property(get_mcafee_system_tray_icon, set_mcafee_system_tray_icon)

    #   Allow end users to update security from the McAfee system tray menu
    def get_allow_update_security(self):
        """
        Get state of Allow end users to update security from the McAfee system tray menu
        """
        return self.get_setting_value('General', 'bAllowUpdateSecurity')

    def set_allow_update_security(self, mode):
        """
        Set state of Allow end users to update security from the McAfee system tray menu
        """
        return self.set_setting_value('General', 'bAllowUpdateSecurity', mode)

    allow_update_security = property(set_allow_update_security, get_allow_update_security)

    #   Enable McAfee system tray icon in a remote desktop session
    def get_mcafee_system_tray_icon_rdp(self):
        """
        Get state of Enable McAfee system tray icon in a remote desktop session
        """
        return self.get_setting_value('General', 'bAllowMcTrayRDP')

    def set_mcafee_system_tray_icon_rdp(self, mode, force=False):
        """
        Set state of Enable McAfee system tray icon in a remote desktop session
        """
        return self.set_setting_value('General', 'bAllowMcTrayRDP', mode, force)

    mcafee_system_tray_icon_rdp = property(get_mcafee_system_tray_icon_rdp,
                                           set_mcafee_system_tray_icon_rdp)

    #   Enable agent wake-up call support
    def get_agent_wakeup_call(self):
        """
        Get state of Enable agent wake-up call support
        """
        value = self.get_setting_value('HttpServerService', 'IsAgentPingEnabled')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bEnableAgentPing')

    def set_agent_wakeup_call(self, mode):
        """
        Set state of Enable agent wake-up call support
        """
        self.set_setting_value('HttpServerService', 'IsAgentPingEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableAgentPing', mode)

    agent_wakeup_call = property(get_agent_wakeup_call, set_agent_wakeup_call)

    #   Enable super agent wake-up call support
    def get_super_agent_wakeup_call(self):
        """
        Get state of Enable super agent wake-up call support
        """
        value = self.get_setting_value('UdpService', 'IsBroadcastPingEnabled')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bEnableBroadcastPing')

    def set_super_agent_wakeup_call(self, mode):
        """
        Set state of Enable super agent wake-up call support
        """
        self.set_setting_value('UdpService', 'IsEnabled', mode)
        self.set_setting_value('UdpService', 'IsBroadcastPingEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableBroadcastPing', mode)

    super_agent_wakeup_call = property(get_super_agent_wakeup_call,
                                       set_super_agent_wakeup_call)

    #   Accept connections only from the ePO server
    def get_listen_eposerver_only(self):
        """
        Get state of Accept connections only from the ePO server
        """
        value = self.get_setting_value('HttpServerService', 'IsListenToEPOServerOnly')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bListenToEPOServerOnly')

    def set_listen_eposerver_only(self, mode):
        """
        Set state of Accept connections only from the ePO server
        """
        self.set_setting_value('HttpServerService', 'IsListenToEPOServerOnly', mode)
        return self.set_setting_value('AgentListenServer', 'bListenToEPOServerOnly', mode)

    listen_eposerver_only = property(get_listen_eposerver_only, set_listen_eposerver_only)

    #   Run agent processes at lower CPU priority (Windows only)
    def get_reduce_process_priority(self):
        """
        Get state of Run agent processes at lower CPU priority (Windows only)
        """
        return self.get_setting_value('General', 'ReduceProcessPriority')

    def set_reduce_process_priority(self, mode):
        """
        Set state of Run agent processes at lower CPU priority (Windows only)
        """
        return self.set_setting_value('General', 'ReduceProcessPriority', mode)

    reduce_process_priority = property(get_reduce_process_priority, set_reduce_process_priority)

    #   Enable self protection (Windows only)
    def get_self_protection(self):
        """
        Get state of Enable self protection (Windows only)
        """
        return self.get_setting_value('General', 'IsSelfProtectionEnabled')

    def set_self_protection(self, mode):
        """
        Set state of Enable self protection (Windows only)
        """
        return self.set_setting_value('General', 'IsSelfProtectionEnabled', mode)

    self_protection = property(get_self_protection, set_self_protection)

    #   Enable msgbus authentication using test certificates
    def get_test_cert_authentication(self):
        """
        Get state of Enable msgbus authentication using test certificates
        """
        return self.get_setting_value('General', 'IsTestCertAuthenticationEnabled')

    def set_test_cert_authentication(self, mode):
        """
        Set state of Enable msgbus authentication using test certificates
        """
        if mode == '1':
            f_root = open('__root__.ca', 'rt')
            root_ca = f_root.read()
            f_root.close()
            self.set_setting_value('General', 'TestCertRootCA', root_ca)
            f_signer = open('__signer__.ca', 'rt')
            signer_ca = f_signer.read()
            f_signer.close()
            self.set_setting_value('General', 'TestCertSignerCA', signer_ca)
        else:
            self.set_setting_value('General', 'TestCertRootCA', '')
            self.set_setting_value('General', 'TestCertSignerCA', '')
        return self.set_setting_value('General', 'IsTestCertAuthenticationEnabled', mode)

    get_test_cert_authentication = property(get_test_cert_authentication,
                                            set_test_cert_authentication)

    # ------------------------------ GENERAL TAB ------------------------------
    # Reboot options after product deployment (Windows only):
    #    Prompt user when a reboot is required
    def get_prompt_user_on_reboot(self):
        """
        Get state of Prompt user when a reboot is required
        """
        value = self.get_setting_value('UpdaterService', 'EnableRebootUI')
        return value if value is not None else self.get_setting_value('General', 'ShowRebootUI')

    def set_prompt_user_on_reboot(self, mode):
        """
        Set state of Prompt user when a reboot is required
        """
        self.set_setting_value('UpdaterService', 'EnableRebootUI', mode)
        return self.set_setting_value('General', 'ShowRebootUI', mode)

    prompt_user_on_reboot = property(get_prompt_user_on_reboot, get_prompt_user_on_reboot)

    #    Force automatic reboot after (seconds):
    def get_auto_reboot_after(self):
        """
        Get Force automatic reboot after (seconds)
        """
        return int(self.get_setting_value('General', 'RebootTimeOut'))

    def set_auto_reboot_after(self, int_seconds):
        """
        Set Force automatic reboot after (seconds)
        Possible values:
            -1  :to disable automatic reboot
            1-n :seconds to wait after before automatic reboot
        """
        return self.set_setting_value('General', 'RebootTimeOut', str(int_seconds))

    auto_reboot_after = property(get_auto_reboot_after, set_auto_reboot_after)

    # ------------------------------ GENERAL TAB ------------------------------
    # Agent-server communication:
    #   Enable agent-to-server communication
    def get_agent_server_communication(self):
        """
        Get state of Enable agent-to-server communication
        """
        return self.get_setting_value('Network', 'bAgentASCI')

    def set_agent_server_communication(self, mode):
        """
        Set state of Enable agent-to-server communication
        """
        return self.set_setting_value('Network', 'bAgentASCI', mode)

    agent_server_communication = property(get_agent_server_communication,
                                          set_agent_server_communication)

    #   Agent-to-server communication interval (minutes):
    def get_asci(self):
        """
        Get Agent-to-server communication interval (minutes).
        """
        value = self.get_setting_value('PropertyService', 'PropertyCollectionTimeout')
        return int(value) if value is not None else int(self.get_setting_value(
            'Network', 'CheckNetworkMessageInterval'))/60

    def set_asci(self, int_minutes):
        """
        Set Agent-to-server communication interval (minutes)
        """
        if int_minutes < 5:
            raise ValueError('Interval below 5 minutes is not possible.')
        self.set_setting_value('PropertyService', 'PropertyCollectionTimeout', str(int_minutes))
        return self.set_setting_value('Network', 'CheckNetworkMessageInterval', str(int_minutes*60))

    asci = property(get_asci, set_asci)

    #   Initiate agent-to-server communication within 10 minutes
    #   after startup if policies are older than (days):
    def get_asci_do_when(self):
        """
        Get Initiate agent-to-server communication within 10 minutes
            after startup if policies are older than (days)
        """
        value = self.get_setting_value('PropertyService', 'PropertyCollectionIfDelayByDays')
        return int(value) if value is not None else int(
            self.get_setting_value('Network', 'AsciDoWhen'))

    def set_asci_do_when(self, int_days):
        """
        Set Initiate agent-to-server communication within 10 minutes
            after startup if policies are older than (days)
        """
        self.set_setting_value('PropertyService', 'PropertyCollectionIfDelayByDays', str(int_days))
        return self.set_setting_value('Network', 'AsciDoWhen', str(int_days))

    asci_do_when = property(get_asci_do_when, set_asci_do_when)

    #   Retrieve all system and product properties (recommended).
    #   If unchecked retrieve only a subset of properties.
    def get_retrieve_full_props(self):
        """
        Get state of Retrieve all system and product properties (recommended).
        """
        value = self.get_setting_value('PropertyService', 'PropertyCollectFullProps')
        return value if value is not None else self.get_setting_value(
            'General', 'bCollectFullProps')

    def set_retrieve_full_props(self, mode):
        """
        Set state of Retrieve all system and product properties (recommended).

        Note: If unchecked retrieve only a subset of properties.
        """
        self.set_setting_value('PropertyService', 'PropertyCollectFullProps', mode)
        return self.set_setting_value('General', 'bCollectFullProps', mode)

    retrieve_full_props = property(get_retrieve_full_props, set_retrieve_full_props)

    # ------------------------------ SUPER-AGENT TAB ------------------------------
    # Repository options:
    #   Convert agents to SuperAgents
    def get_super_agent(self):
        """
        Get state of Convert agents to SuperAgents
        """
        value = self.get_setting_value('HttpServerService', 'IsSuperAgentEnabled')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bEnableSuperAgent')

    def set_super_agent(self, mode):
        """
        Set state of Convert agents to SuperAgents
        """
        self.set_setting_value('HttpServerService', 'IsSuperAgentEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableSuperAgent', mode)

    super_agent = property(get_super_agent, set_super_agent)

    #   Use systems running SuperAgents as distributed repositories
    def get_sa_repository(self):
        """
        Get state of Use systems running SuperAgents as distributed repositories
        """
        value = self.get_setting_value('HttpServerService', 'IsSuperAgentRepositoryEnabled')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bEnableSuperAgentRepository')

    def set_sa_repository(self, mode):
        """
        Set state of Use systems running SuperAgents as distributed repositories
        """
        self.set_setting_value('HttpServerService', 'IsSuperAgentRepositoryEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableSuperAgentRepository', mode)

    sa_repository = property(get_sa_repository, set_sa_repository)

    #   Repository path (Windows)
    def get_sa_repo_path_windows(self):
        """
        Get Repository path (Windows)
        """
        value = self.get_setting_value('HttpServerService', 'VirtualDirectory')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'VirtualDirectory')

    def set_sa_repo_path_windows(self, path):
        """
        Set Repository path (Windows)
        """
        self.set_setting_value('HttpServerService', 'VirtualDirectory', path)
        return self.set_setting_value('AgentListenServer', 'VirtualDirectory', path)

    sa_repo_path_windows = property(get_sa_repo_path_windows, set_sa_repo_path_windows)

    #   Repository path (Unix)
    def get_sa_repo_path_unix(self):
        """
        Get Repository path (Unix)
        """
        value = self.get_setting_value('HttpServerService', 'VirtualDirectoryUnix')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'VirtualDirectoryUnix')

    def set_sa_repo_path_unix(self, path):
        """
        Set Repository path (Unix)
        """
        self.set_setting_value('HttpServerService', 'VirtualDirectoryUnix', path)
        return self.set_setting_value('AgentListenServer', 'VirtualDirectoryUnix', path)

    sa_repo_path_unix = property(get_sa_repo_path_unix, set_sa_repo_path_unix)

    #   Enable LazyCaching (Ensure one or more Repository is enabled)
    def get_sa_lazy_caching(self):
        """
        Get state of Enable LazyCaching
        """
        return self.get_setting_value('HttpServerService', 'IsLazyCachingEnabled')

    def set_sa_lazy_caching(self, mode):
        """
        Set Enable LazyCaching

        Note: Ensure one or more Repository is enabled.
        """
        return self.set_setting_value('HttpServerService', 'IsLazyCachingEnabled', mode)

    sa_lazy_caching = property(get_sa_lazy_caching, set_sa_lazy_caching)

    #   Interval to flush cache (minutes):
    def get_sa_cache_sync_interval(self):
        """
        Get Interval to flush cache (minutes)
        """
        value = self.get_setting_value('HttpServerService', 'RepositorySyncInterval')
        return int(value) if value is not None else int(self.get_setting_value(
            'AgentListenServer', 'NewRepositoryContentInterval'))

    def set_sa_cache_sync_interval(self, int_minutes):
        """
        Set Interval to flush cache (minutes)
        """
        self.set_setting_value('HttpServerService', 'RepositorySyncInterval', str(int_minutes))
        return self.set_setting_value(
            'AgentListenServer', 'NewRepositoryContentInterval', str(int_minutes))

    sa_cache_sync_interval = property(get_sa_cache_sync_interval, set_sa_cache_sync_interval)

    #   Max disk quota (GB):
    def get_sa_cache_disk_quota(self):
        """
        Get Max disk quota (GB)
        """
        value = self.get_setting_value('HttpServerService', 'DiskQuota')
        return int(value) if value is not None else int(
            self.get_setting_value('AgentListenServer', 'LCDiskQuota'))

    def set_sa_cache_disk_quota(self, int_gigabytes):
        """
        Set Max disk quota (GB):
        """
        self.set_setting_value('HttpServerService', 'DiskQuota', str(int_gigabytes))
        return self.set_setting_value('AgentListenServer', 'LCDiskQuota', str(int_gigabytes))

    sa_cache_disk_quota = property(get_sa_cache_disk_quota, set_sa_cache_disk_quota)

    #   Purge Interval (Days):
    def get_sa_cache_purge_interval(self):
        """
        Get Purge Interval (Days)
        """
        value = self.get_setting_value('HttpServerService', 'ContentLongevity')
        return int(value) if value is not None else int(
            self.get_setting_value('AgentListenServer', 'ContentLongevity'))

    def set_sa_cache_purge_interval(self, int_days):
        """
        Set Purge Interval (Days)
        """
        self.set_setting_value('HttpServerService', 'ContentLongevity', str(int_days))
        return self.set_setting_value('AgentListenServer', 'ContentLongevity', str(int_days))

    sa_cache_purge_interval = property(get_sa_cache_purge_interval, set_sa_cache_purge_interval)

    # Relay Client options:
    #   Enable Relay Communication
    def get_relay_client(self):
        """
        Get state of Enable Relay Communication
        """
        value = self.get_setting_value('RelayService', 'EnableClient')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'IsRelayClientEnabled')

    def set_relay_client(self, mode):
        """
        Set state of Enable Relay Communication
        """
        self.set_setting_value('RelayService', 'EnableClient', mode)
        return self.set_setting_value('AgentListenServer', 'IsRelayClientEnabled', mode)

    relay_client = property(get_relay_client, set_relay_client)

    #   Disable Discovery
    def get_relay_disable_discovery(self):
        """
        Get state of Disable Discovery
        """
        return self.get_setting_value('RelayService', 'IsRelayDiscoveryDisabled')

    def set_relay_disable_discovery(self, mode):
        """
        Set state of Disable Discovery
        """
        return self.set_setting_value('RelayService', 'IsRelayDiscoveryDisabled', mode)

    relay_disable_discovery = property(get_relay_disable_discovery, set_relay_disable_discovery)

    def get_relay_server_list(self):
        """
        Get the Relay Server list
        """
        table = None
        section = 'RelayService'
        keys = ['relayselect', 'relayip', 'relayport']
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is not None:
            setting_obj = section_obj.find('Setting[@name="RelayServerCount"]')
            max_rows = int(setting_obj.get('value'))
            max_cols = len(keys)
            table = []
            for row in range(1, max_rows+1):
                row_value = {}
                for col in range(max_cols):
                    setting_obj = section_obj.find('Setting[@name="{}_{}"]'.format(keys[col], row))
                    row_value[keys[col]] = setting_obj.get('value')
                table.append(row_value)
        return table

    def set_relay_server_list(self, table):
        """
        Set the Relay Server list
        """
        success = False
        section = 'RelayService'
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is not None:
            success = True
            max_rows = len(table)
            keys = table[0].keys()
            # Remove existing entries
            for setting_obj in section_obj.findall('Setting'):
                if ('relayip' in setting_obj.attrib['name'] or
                        'relayselect' in setting_obj.attrib['name'] or
                        'relayport' in setting_obj.attrib['name']):
                    section_obj.remove(setting_obj)
            setting_obj = section_obj.find('Setting[@name="RelayServerCount"]')
            if setting_obj is not None:
                section_obj.remove(setting_obj)
            # Create Tag with Value with the current table
            et.SubElement(section_obj,
                          'Setting',
                          {"name":'RelayServerCount', "value":str(max_rows)})
            for row in range(max_rows):
                for key in keys:
                    et.SubElement(section_obj,
                                  'Setting',
                                  {"name":'{}_{}'.format(key, row+1), "value":table[row][key]})
        return success

    relay_server_list = property(get_relay_server_list, set_relay_server_list)

    # RelayServer options:
    #   Enable RelayServer
    def get_relay_server(self):
        """
        Get state of Enable RelayServer
        """
        value = self.get_setting_value('RelayService', 'IsEnabled')
        return value if value is not None else self.get_setting_value(
            'AgentListenServer', 'bEnableRelayService')

    def set_relay_server(self, mode):
        """
        Set state of Enable RelayServer
        """
        self.set_setting_value('RelayService', 'IsEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableRelayService', mode)

    relay_server = property(get_relay_server, set_relay_server)

    #   Service Manager port (RelayServer):
    def get_relay_server_port(self):
        """
        Get Service Manager port (RelayServer)
        """
        value = self.get_setting_value('RelayService', 'RelayServerPort')
        return int(value) if value is not None else int(
            self.get_setting_value('AgentListenServer', 'AgtServiceMgrPort'))

    def set_relay_server_port(self, int_port):
        """
        Set Service Manager port (RelayServer)
        """
        self.set_setting_value('RelayService', 'RelayServerPort', str(int_port))
        return self.set_setting_value('AgentListenServer', 'AgtServiceMgrPort', str(int_port))

    relay_server_port = property(get_relay_server_port, set_relay_server_port)

    # ------------------------------ EVENTS TAB ------------------------------
    # Priority event forwarding:
    #    Enable priority event forwarding
    def get_events_priority_forwarding(self):
        """
        Get state of Enable priority event forwarding
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEnableEventTrigger')
        return value if value is not None else self.get_setting_value(
            'EventService', 'EventIsEnabledPriorityForward')

    def set_events_priority_forwarding(self, mode, force=False):
        """
        Set state of Enable priority event forwarding
        """
        self.set_setting_value('AgentEvents', 'AgPlcyEnableEventTrigger', mode, force)
        return self.set_setting_value('EventService', 'EventIsEnabledPriorityForward', mode, force)

    events_priority_forwarding = property(get_events_priority_forwarding,
                                          set_events_priority_forwarding)

    #   Forward events with a priority equal or greater than:
    def get_events_priority_level(self):
        """
        Get Forward events with a priority equal or greater than
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEventTriggerThreshold')
        return value if value is not None else self.get_setting_value(
            'EventService', 'EventPriorityLevel')

    def set_events_priority_level(self, level, force=False):
        """
        Set Forward events with a priority equal or greater than
        """
        if level not in ['0', '1', '2', '3', '4']:
            raise ValueError('Priority level must be within ["0", "1", "2", "3", "4"].')
        self.set_setting_value('AgentEvents', 'AgPlcyEventTriggerThreshold', level, force)
        return self.set_setting_value('EventService', 'EventPriorityLevel', level, force)

    events_priority_level = property(get_events_priority_level, set_events_priority_level)

    #   Interval between uploads (minutes):
    def get_events_upload_interval(self):
        """
        Get  Interval between uploads (minutes)
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEventTriggerDelayMins')
        return int(value) if value is not None else int(
            self.get_setting_value('EventService', 'EventUploadTimeout'))

    def set_events_upload_interval(self, int_minutes, force=False):
        """
        Set  Interval between uploads (minutes)
        """
        if int_minutes < 1:
            raise ValueError('Interval must be greater than 1 minute.')
        self.set_setting_value('AgentEvents', 'AgPlcyEventTriggerDelayMins',
                               str(int_minutes), force)
        return self.set_setting_value('EventService', 'EventUploadTimeout', str(int_minutes), force)

    events_upload_interval = property(get_events_upload_interval, set_events_upload_interval)

    #   Maximum number of events per upload:
    def get_events_max_per_upload(self):
        """
        Get Maximum number of events per upload:
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyMaxEventsPerTrigger')
        return int(value) if value is not None else int(
            self.get_setting_value('EventService', 'EventUploadThreshold'))

    def set_events_max_per_upload(self, int_events, force=False):
        """
        Set Maximum number of events per upload:
        """
        if int_events < 1:
            raise ValueError('Number of events must be greater than 1.')
        self.set_setting_value('AgentEvents', 'AgPlcyMaxEventsPerTrigger', str(int_events), force)
        return self.set_setting_value('EventService', 'EventUploadThreshold',
                                      str(int_events), force)

    events_max_per_upload = property(get_events_max_per_upload, set_events_max_per_upload)

    # ------------------------------ LOGGING TAB ------------------------------
    # Application logging:
    #   Enable application logging
    def get_log_application(self):
        """
        Get state of Enable application logging
        """
        value = self.get_setting_value('AgentLogging', 'IsApplicationLogEnabled')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsApplicationLogEnabled')

    def set_log_application(self, mode, force=False):
        """
        Set Enable application logging
        """
        self.set_setting_value('AgentLogging', 'IsApplicationLogEnabled', mode, force)
        return self.set_setting_value('LoggerService', 'IsApplicationLogEnabled', mode, force)

    log_application = property(get_log_application, set_log_application)

    #   Enable detailed logging
    def get_log_detailed(self):
        """
        Get state of Enable detailed logging
        """
        value = self.get_setting_value('AgentLogging', 'bVerbose')
        return value if value is not None else self.get_setting_value('LoggerService', 'bVerbose')

    def set_log_detailed(self, mode, force=False):
        """
        Set Enable detailed logging
        """
        self.set_setting_value('AgentLogging', 'bVerbose', mode, force)
        return self.set_setting_value('LoggerService', 'bVerbose', mode, force)

    log_detailed = property(get_log_detailed, set_log_detailed)

    #   Log file size limit (MB):
    def get_log_limit(self):
        """
        Get Log file size limit (MB)
        """
        value = self.get_setting_value('AgentLogging', 'LogSizeLimit')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogSizeLimit'))

    def set_log_limit(self, int_megabytes, force=False):
        """
        Set Log file size limit (MB)
        """
        if int_megabytes < 1:
            raise ValueError('Number of megabytes must be greater than 0.')
        self.set_setting_value('AgentLogging', 'LogSizeLimit', str(int_megabytes), force)
        return self.set_setting_value('LoggerService', 'LogSizeLimit', str(int_megabytes), force)

    log_limit = property(get_log_limit, set_log_limit)

    #   Roll over count:
    def get_log_roll_over(self):
        """
        Get Roll over count
        """
        value = self.get_setting_value('AgentLogging', 'LogMaxRollover')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogMaxRollover'))

    def set_log_roll_over(self, int_count, force=False):
        """
        Set Roll over count
        """
        if int_count < 1:
            raise ValueError('Number of files count must be greater than 0.')
        self.set_setting_value('AgentLogging', 'LogMaxRollover', str(int_count), force)
        return self.set_setting_value('LoggerService', 'LogMaxRollover', str(int_count), force)

    log_roll_over = property(get_log_roll_over, get_log_roll_over)

    # Remote logging:
    #   Enable remote Logging
    def get_log_remote(self):
        """
        Get state of Enable remote Logging
        """
        value = self.get_setting_value('AgentLogging', 'bEnableLog')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsLogRecordingEnabled')

    def set_log_remote(self, mode, force=False):
        """
        Set state of Enable remote Logging
        """
        self.set_setting_value('AgentLogging', 'bEnableLog', mode, force)
        return self.set_setting_value('LoggerService', 'IsLogRecordingEnabled', mode, force)

    log_remote = property(get_log_remote, set_log_remote)

    #   Limit in lines:
    def get_log_remote_limit(self):
        """
        Get Limit in lines
        """
        value = self.get_setting_value('AgentLogging', 'nLogSizeLimit')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogRecordsSize'))

    def set_log_remote_limit(self, int_lines, force=False):
        """
        Set Limit in lines
        """
        if int_lines < 1:
            raise ValueError('Number of lines must be greater than 0.')
        self.set_setting_value('AgentLogging', 'nLogSizeLimit', str(int_lines), force)
        return self.set_setting_value('LoggerService', 'LogRecordsSize', str(int_lines), force)

    log_remote_limit = property(get_log_remote_limit, set_log_remote_limit)

    #   Enable remote access to log
    def get_log_remote_access(self):
        """
        Get state of Enable remote access to log
        """
        value = self.get_setting_value('AgentLogging', 'bEnableRemoteLog')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsRemoteLogEnabled')

    def set_log_remote_access(self, mode, force=False):
        """
        Set state of Enable remote access to log
        """
        self.set_setting_value('AgentLogging', 'bEnableRemoteLog', mode, force)
        return self.set_setting_value('LoggerService', 'IsRemoteLogEnabled', mode, force)

    log_remote_access = property(get_log_remote_access, set_log_remote_access)

    # ------------------------------ UPDATES TAB ------------------------------
    # Product update log file:
    def get_upd_log_file(self):
        """
        Get Product update log file
        """
        value = self.get_setting_value('UpdateOptions', 'szLogFileName')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'UpdateLogFileName')

    def set_upd_log_file(self, path, force=False):
        """
        Set Product update log file
        """
        self.set_setting_value('UpdateOptions', 'szLogFileName', path, force)
        return self.set_setting_value('UpdaterService', 'UpdateLogFileName', path, force)

    upd_log_file = property(get_upd_log_file, set_upd_log_file)

    # Post-update options:
    #   Enter an executable to run after an update completes:
    def get_upd_run_exe(self):
        """
        Get Enter an executable to run after an update completes
        """
        value = self.get_setting_value('UpdateOptions', 'szRunAfterUpdateEXE')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'ExeNameToRunAfterUpdate')

    def set_upd_run_exe(self, path, force=False):
        """
        Set Enter an executable to run after an update completes
        """
        self.set_setting_value('UpdateOptions', 'szRunAfterUpdateEXE', path, force)
        return self.set_setting_value('UpdaterService', 'ExeNameToRunAfterUpdate', path, force)

    upd_run_exe = property(get_upd_run_exe, set_upd_run_exe)

    #   Run only after successful updates
    def get_upd_run_exe_after_success(self):
        """
        Get state of Run only after successful updates
        """
        value = self.get_setting_value('UpdateOptions', 'bRunIfUpdateSuccess')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableExeAfterUpdate')

    def set_upd_run_exe_after_success(self, mode, force=False):
        """
        Set state of Run only after successful updates
        """
        self.set_setting_value('UpdateOptions', 'bRunIfUpdateSuccess', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableExeAfterUpdate', mode, force)

    upd_run_exe_after_success = property(get_upd_run_exe_after_success,
                                         set_upd_run_exe_after_success)

    #   DAT file downgrades: Enable DAT file downgrades when the version
    #   in the repository is older than local version
    def get_upd_dat_downgrade(self):
        """
        Get state of Enable DAT file downgrades when the version
            in the repository is older than local version
        """
        value = self.get_setting_value('UpdateOptions', 'bAllowDATDowngrade')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableDatDowngrade')

    def set_upd_dat_downgrade(self, mode, force=False):
        """
        Set state of Enable DAT file downgrades when the version
            in the repository is older than local version
        """
        self.set_setting_value('UpdateOptions', 'bAllowDATDowngrade', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableDatDowngrade', mode, force)

    upd_dat_downgrade = property(get_upd_dat_downgrade, set_upd_dat_downgrade)

    # Update options: Enable update after deployment
    def get_upd_after_deployment(self):
        """
        Get state of Enable update after deployment
        """
        value = self.get_setting_value('UpdateOptions', 'bUpdateAfterDeployment')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableUpdateAfterDeployment')

    def set_upd_after_deployment(self, mode, force=False):
        """
        Set state of Enable update after deployment
        """
        self.set_setting_value('UpdateOptions', 'bUpdateAfterDeployment', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableUpdateAfterDeployment', mode, force)

    upd_after_deployment = property(get_upd_after_deployment, set_upd_after_deployment)

    # Update type and Repository branch to use:
    def get_upd_branch_selection(self):
        """
        Get  Update type and Repository branch to use
        """
        keys = ['BranchType', 'OneClickEnabled', 'SoftwareID']
        return self.get_table_value('BranchSelection', keys)

    def set_upd_branch_selection(self, table):
        """
        Set  Update type and Repository branch to use
        """
        return self.set_table_value('BranchSelection', table)

    upd_branch_selection = property(get_upd_branch_selection, set_upd_branch_selection)

    # ------------------------------ PEER-TO-PEER TAB ------------------------------
    # Peer-to-Peer Options:
    #   Enable Peer-to-Peer Communication
    def get_p2p_client(self):
        """
        Get state of Enable Peer-to-Peer Communication
        """
        return self.get_setting_value('P2pService', 'EnableClient')

    def set_p2p_client(self, mode):
        """
        Set state of Enable Peer-to-Peer Communication
        """
        return self.set_setting_value('P2pService', 'EnableClient', mode)

    p2p_client = property(get_p2p_client, get_p2p_client)

    #   Enable Peer-to-Peer Serving
    def get_p2p_server(self):
        """
        Get state of Enable Peer-to-Peer Serving
        """
        return self.get_setting_value('P2pService', 'EnableServing')

    def set_p2p_server(self, mode):
        """
        Set state of Enable Peer-to-Peer Serving
        """
        return self.set_setting_value('P2pService', 'EnableServing', mode)

    p2p_server = property(get_p2p_server, set_p2p_server)

    #   Repository path (Windows):
    def get_p2p_repo_path(self):
        """
        Get Repository path (Windows)
        """
        return self.get_setting_value('P2pService', 'P2pRepoPath')

    def set_p2p_repo_path(self, path):
        """
        Set Repository path (Windows)
        """
        return self.set_setting_value('P2pService', 'P2pRepoPath', path)

    p2p_repo_path = property(get_p2p_repo_path, set_p2p_repo_path)

    #   Repository path (Unix):
    def get_p2p_repo_path_unix(self):
        """
        Get Repository path (Unix)
        """
        return self.get_setting_value('P2pService', 'P2pRepoPathUnix')

    def set_p2p_repo_path_unix(self, path):
        """
        Set Repository path (Unix)
        """
        return self.set_setting_value('P2pService', 'P2pRepoPathUnix', path)

    p2p_repo_path_unix = property(get_p2p_repo_path_unix, set_p2p_repo_path_unix)

    #   Max disk quota (MB):
    def get_p2p_disk_quota(self):
        """
        Get Max disk quota (MB)
        """
        return int(self.get_setting_value('P2pService', 'DiskQuota'))

    def set_p2p_disk_quota(self, int_in_megabytes):
        """
        Set Max disk quota (MB)
        """
        return self.set_setting_value('P2pService', 'DiskQuota', str(int_in_megabytes))

    p2p_disk_quota = property(get_p2p_disk_quota, set_p2p_disk_quota)

    #   Purge Interval (Days):
    def get_p2p_purge_interval(self):
        """
        Get Purge Interval (Days)
        """
        return int(self.get_setting_value('P2pService', 'ContentLongevity'))

    def set_p2p_purge_interval(self, int_in_days):
        """
        Set Purge Interval (Days)
        """
        return self.set_setting_value('P2pService', 'ContentLongevity', str(int_in_days))

    p2p_purge_interval = property(get_p2p_purge_interval, set_p2p_purge_interval)

    # ------------------------------ DEPLOYMENT TAB ------------------------------
    # Incompatibility check:
    #   Enable Incompatibility check
    def get_dep_compatibility_check(self):
        """
        Get state of Enable Incompatibility check
        """
        return self.get_setting_value('Deployment', 'EnableCompatibilityCheck')

    def set_dep_compatibility_check(self, mode):
        """
        Set state of Enable Incompatibility check
        """
        return self.set_setting_value('Deployment', 'EnableCompatibilityCheck', mode)

    dep_compatibility_check = property(get_dep_compatibility_check, get_dep_compatibility_check)