# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESTPPolicyOnAccessScan.
"""

import xml.etree.ElementTree as et
from ...policies import Policy
from .exclusions import ExclusionList

class ESTPPolicyOnAccessScan(Policy):
    """
    The ESTPPolicyOnAccessScan class can be used to edit the Endpoint Security
    Threat Prevention policy: On-Access Scan.
    """

    def __init__(self, policy_from_estppolicies=None):
        super(ESTPPolicyOnAccessScan, self).__init__(policy_from_estppolicies)
        if policy_from_estppolicies is not None:
            if self.get_type() != 'EAM_General_Policies':
                raise ValueError('Wrong policy! Policy type must be "EAM_General_Policies".')

    def __repr__(self):
        return 'ESTPPolicyOnAccessScan()'

    # ------------------------------ On-Access Policy ------------------------------
    # On-Access Scan:
    #   Enable On-Access Scan
    def get_on_access_scan(self):
        """
        Get the On-Access Scan feature state
        """
        return self.get_setting_value('General', 'bOASEnabled')

    def set_on_access_scan(self, mode):
        """
        Set the On-Access Scan feature state
        """
        return self.set_setting_value('General', 'bOASEnabled', mode)

    on_access_scan = property(get_on_access_scan, set_on_access_scan)

    #	Enable On-Access Scan on system startup
    def get_scan_on_startup(self):
        """
        Get the On-Access Scan on system startup state
        """
        return self.get_setting_value('General', 'bStartEnabled')

    def set_scan_on_startup(self, mode):
        """
        Set the On-Access Scan on system startup state
        """
        return self.set_setting_value('General', 'bStartEnabled', mode)

    scan_on_startup = property(get_scan_on_startup, set_scan_on_startup)

	#	Allow users to disable On-Access Scan from the McAfee system tray icon
    def get_allow_user_to_disable_oas(self):
        """
        Get state of Allow users to disable On-Access Scan from the McAfee system tray icon
        """
        return self.get_setting_value('General', 'bAllowDisableViaMcTray')

    def set_allow_user_to_disable_oas(self, mode):
        """
        Set state of Allow users to disable On-Access Scan from the McAfee system tray icon
        """
        return self.set_setting_value('General', 'bAllowDisableViaMcTray', mode)

    allow_user_to_disable_oas = property(get_allow_user_to_disable_oas,
                                         set_allow_user_to_disable_oas)

    #	Specify maximum number of seconds for each file scan
    def get_max_scan_time_enforced(self):
        """
        Get if maximum scan time is enforced
        """
        return self.get_setting_value('General', 'bEnforceMaxScanTime')

    def set_max_scan_time_enforced(self, mode):
        """
        Set enforcement of maximum scan time
        """
        return self.set_setting_value('General', 'bEnforceMaxScanTime', mode)

    max_scan_time_enforced = property(get_max_scan_time_enforced, set_max_scan_time_enforced)

    def get_max_scan_time(self):
        """
        Get the maximum number of seconds for each file scan
        """
        return int(self.get_setting_value('General', 'dwScannerThreadTimeout'))

    def set_max_scan_time(self, int_seconds):
        """
        Set the maximum number of seconds for each file scan
        """
        if int_seconds < 10:
            raise ValueError('Timeout below 10 seconds is not accepted.')
        return self.set_setting_value('General', 'dwScannerThreadTimeout', int_seconds)

    max_scan_time = property(get_max_scan_time, set_max_scan_time)

    #	Scan boot sectors
    def get_scan_boot_sectors(self):
        """
        Get state of Scan boot sectors
        """
        return self.get_setting_value('General', 'bScanBootSectors')

    def set_scan_boot_sectors(self, mode):
        """
        Set state of Scan boot sectors
        """
        return self.set_setting_value('General', 'bScanBootSectors', mode)

    scan_boot_sectors = property(get_scan_boot_sectors, set_scan_boot_sectors)

    #	Scan processes on service startup and content update
    def get_scan_process_startup(self):
        """
        Get state of Scan processes on service startup and content update
        """
        return self.get_setting_value('General', 'scanProcessesOnEnable')

    def set_scan_process_startup(self, mode):
        """
        Set state of Scan processes on service startup and content update
        """
        return self.set_setting_value('General', 'scanProcessesOnEnable', mode)

    scan_process_startup = property(get_scan_process_startup, set_scan_process_startup)

    #	Scan trusted installers
    def get_scan_trusted_installers(self):
        """
        Get state of Scan trusted installers
        """
        return self.get_setting_value('General', 'scanTrustedInstallers')

    def set_scan_trusted_installers(self, mode):
        """
        Set state of Scan trusted installers
        """
        return self.set_setting_value('General', 'scanTrustedInstallers', mode)

    scan_trusted_installers = property(get_scan_trusted_installers, set_scan_trusted_installers)

    #	Scan when copying between local folders
    def get_scan_copy_between_local_folders(self):
        """
        Get state of Scan when copying between local folders
        """
        return self.get_setting_value('General', 'scanCopyLocalFolders')

    def set_scan_copy_between_local_folders(self, mode):
        """
        Set state of Scan when copying between local folders
        """
        return self.set_setting_value('General', 'scanCopyLocalFolders', mode)

    scan_copy_between_local_folders = property(get_scan_copy_between_local_folders,
                                               set_scan_copy_between_local_folders)

    #	Scan when copying from network folders and removable drives
    def get_scan_copy_from_network(self):
        """
        Get state of Scan when copying from network folders and removable drives
        """
        return self.get_setting_value('General', 'scanCopyNetworkRemovable')

    def set_scan_copy_from_network(self, mode):
        """
        Set state of Scan when copying from network folders and removable drives
        """
        return self.set_setting_value('General', 'scanCopyNetworkRemovable', mode)

    scan_copy_from_network = property(get_scan_copy_from_network, set_scan_copy_from_network)

    #	Detect suspicious email attachments
    def get_scan_email_attachments(self):
        """
        Get state of Detect suspicious email attachments
        """
        return self.get_setting_value('General', 'scanEmailAttachments')

    def set_scan_email_attachments(self, mode):
        """
        Set state of Detect suspicious email attachments
        """
        return self.set_setting_value('General', 'scanEmailAttachments', mode)

    scan_email_attachments = property(get_scan_email_attachments, set_scan_email_attachments)

    #	Disable read/write scan of Shadow Copy volumes for SYSTEM process (improves performance)
    def get_scan_shadow_copy(self):
        """
        Get state of Read/Write scan of Shadow Copy volumes for SYSTEM process
        """
        mode = self.get_setting_value('General', 'scanShadowCopyDisableStatus')
        return '0' if mode == '1' else '1'

    def set_scan_shadow_copy(self, mode):
        """
        Set state of Read/Write scan of Shadow Copy volumes for SYSTEM process
        """
        mode = '0' if mode == '1' else '1'
        return self.set_setting_value('General', 'scanShadowCopyDisableStatus', mode)

    scan_shadow_copy = property(get_scan_shadow_copy, set_scan_shadow_copy)

    # ------------------------------ On-Access Policy ------------------------------
    # McAfee GTI:
    #	Enable McAfee GTI
    #   0 = OFF         Gti().DISABLED
    #   1 = Very Low    Gti().VERY_LOW
    #   2 = Low         Gti().LOW
    #   3 = Medium      Gti().MEDIUM
    #   4 = High        Gti().HIGH
    #   5 = Very High   Gti().VERY_HIGH
    def get_gti_level(self):
        """
        Get the GTI level (Use Gti class from constants)
        """
        return self.get_setting_value('GTI', 'GTISensitivityLevel')

    def set_gti_level(self, level):
        """
        Set the GTI level (Use Gti class from constants)
        """
        if level not in ['0', '1', '2', '3', '4', '5']:
            raise ValueError('GTI sensitivity level must be within ["0", "1", "2", "3", "4", "5"].')
        return self.set_setting_value('GTI', 'GTISensitivityLevel', level)

    gti_level = property(get_gti_level, set_gti_level)

    # ------------------------------ On-Access Policy ------------------------------
    # Antimalware Scan Interface:
    #	Enable AMSI (provides enhanced script scanning)
    def get_scan_amsi(self):
        """
        Get state of Enable AMSI (provides enhanced script scanning)
        """
        return self.get_setting_value('General', 'scanUsingAMSIHooks')

    def set_scan_amsi(self, mode):
        """
        Set state of Enable AMSI (provides enhanced script scanning)
        """
        return self.set_setting_value('General', 'scanUsingAMSIHooks', mode)

    scan_amsi = property(get_scan_amsi, set_scan_amsi)

    #	Enable Observe mode (Events are generated but actions are not enforced)
    def get_scan_amsi_observe_mode(self):
        """
        Get state of Enable AMSI Observe mode (Events are generated but actions are not enforced)
        """
        return self.get_setting_value('General', 'enableAMSIObserveMode')

    def set_scan_amsi_observe_mode(self, mode):
        """
        Set state of Enable AMSI Observe mode (Events are generated but actions are not enforced)
        """
        return self.set_setting_value('General', 'enableAMSIObserveMode', mode)

    scan_amsi_observe_mode = property(get_scan_amsi_observe_mode, set_scan_amsi_observe_mode)

    # ------------------------------ On-Access Policy ------------------------------
    # Threat Detection User Messaging:
    #	Display the On-Access Scan window to users when a threat is detected
    def get_show_alert(self):
        """
        Get state of Display the On-Access Scan window to users when a threat is detected
        """
        return self.get_setting_value('Alerting', 'bShowAlerts')

    def set_show_alert(self, mode):
        """
        Set state of Display the On-Access Scan window to users when a threat is detected
        """
        return self.set_setting_value('Alerting', 'bShowAlerts', mode)

    show_alert = property(get_show_alert, set_show_alert)

    #	Message: (Default = McAfee Endpoint Security detected a threat.)
    def get_alert_message(self):
        """
        Get Threat Detection message
        """
        return self.get_setting_value('Alerting', 'szDialogMessage')

    def set_alert_message(self, str_message="McAfee Endpoint Security detected a threat."):
        """
        Set Threat Detection message (256 caracters maximum)
        """
        if len(str_message) == 0 or len(str_message) > 256:
            raise ValueError('The message cannot be empty or longer than 256 caracters.')
        return self.set_setting_value('Alerting', 'szDialogMessage', str_message)

    alert_message = property(get_alert_message, set_alert_message)

    # ------------------------------ On-Access Policy ------------------------------
    # Process Settings:
    def get_use_standard_settings_only(self):
        """
        Get Use Standard settings for all processes or
        Configure different settings for High Risk and Low Risk processes
        """
        return self.get_setting_value('General', 'bOnlyUseDefaultConfig')

    def set_use_standard_settings_only(self, mode):
        """
        Set Use Standard settings for all processes or
        Configure different settings for High Risk and Low Risk processes
        """
        return self.set_setting_value('General', 'bOnlyUseDefaultConfig', mode)

    use_standard_settings_only = property(get_use_standard_settings_only,
                                          set_use_standard_settings_only)

    # ------------------------------ On-Access Policy ------------------------------
    # Process Settings:
    def get_process_list(self):
        """
        Get the process list
        (Standard settings will apply to all unlisted processes.)
        Return a ProcessList object.
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="Application"]')
        if section_obj is not None:
            setting_obj = section_obj.find('Setting[@name="dwApplicationCount"]')
            max_rows = int(setting_obj.get('value'))
            table = list()
            for row in range(max_rows):
                row_value = list()
                setting_obj = section_obj.find('Setting[@name="szApplicationItem_{}"]'.format(row))
                row_value.append(setting_obj.get('value'))
                setting_obj = section_obj.find('Setting[@name="TypeItem_{}"]'.format(row))
                if setting_obj.get('value') == '0':
                    row_value.append('Low Risk')
                else:
                    row_value.append('High Risk')
                table.append(row_value)
        return table

    def set_process_list(self, table):
        """
        Set the process list with a ProcessList object as input
        Return true or false.
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="Application"]')
        if section_obj is not None:
            success = True
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name='Application')
            if len(table) > 0:
                et.SubElement(section_obj, 'Setting',
                              {"name":'dwApplicationCount', "value":str(len(table))})
                for index, row in enumerate(table):
                    et.SubElement(section_obj, 'Setting',
                                  {"name":'szApplicationItem_{}'.format(index), "value":row[0]})
                    if row[1] == 'Low Risk':
                        et.SubElement(section_obj, 'Setting',
                                      {"name":'TypeItem_x{}'.format(index), "value":'0'})
                    elif row[1] == 'High Risk':
                        et.SubElement(section_obj, 'Setting',
                                      {"name":'TypeItem_x{}'.format(index), "value":'1'})
                    else:
                        raise ValueError('Risk level unknown: {}.'.format(row[1]))
        return success

    process_list = property(get_process_list, set_process_list)

    # ---------------------- On-Access Policy - Standard ---------------------------
    # Process Settings:
    #	Process Type: Standard
    def get_when_to_scan(self, __section__='Default-Detection'):
        """
        Get When to scan, Reading/Writing.
        Returns a int value as following
        '0': Do not scan when reading from or writing to disk
        '1': When writing to disk (deprecated)
        '2': When reading from disk (deprecated)
        '3': Let McAfee decide
        '4': Let me decide, when writing to disk
        '5': Let me decide, when reading from disk
        '6': Let me decide, when writing and reading.
        """
        writing_mode = self.get_setting_value(__section__, 'bScanWriting')
        reading_mode = self.get_setting_value(__section__, 'bScanReading')
        writing_mode_bypass = self.get_setting_value(__section__, 'bScanWritingByPass')
        reading_mode_bypass = self.get_setting_value(__section__, 'bScanReadingByPass')
        if writing_mode_bypass == '2' and reading_mode_bypass == '2':
            level = '6'
        elif reading_mode_bypass == '2':
            level = '5'
        elif writing_mode_bypass == '2':
            level = '4'
        elif writing_mode == '1' and reading_mode == '1':
            level = '3'
        elif reading_mode == '1':
            level = '2'
        elif writing_mode == '1':
            level = '1'
        else:
            level = '0'
        return level

    def set_when_to_scan(self, level, __section__='Default-Detection'):
        """
        Set When to scan, Reading/Writing.
        Use following level as input:
        '0': Do not scan when reading from or writing to disk
        '1': When writing to disk (deprecated)
        '2': When reading from disk (deprecated)
        '3': Let McAfee decide
        '4': Let me decide, when writing to disk
        '5': Let me decide, when reading from disk
        '6': Let me decide, when writing and reading.
        """
        success = False
        if level not in ['0', '1', '2', '3', '4', '5', '6']:
            raise ValueError('Level must be within ["0", "1", "2", "3", "4", "5", "6"].')
        if level == '0' and __section__ != 'LowRisk-Detection':
            raise ValueError('Section must be set to "LowRisk-Detection".')
        success = True
        if level == '0':
            writing_mode = '0'
            reading_mode = '0'
            writing_mode_bypass = '0'
            reading_mode_bypass = '0'
        elif level in ['1', '4']:
            writing_mode = '1'
            reading_mode = '0'
            writing_mode_bypass = '2'
            reading_mode_bypass = '0'
        elif level in ['2', '5']:
            writing_mode = '0'
            reading_mode = '1'
            writing_mode_bypass = '0'
            reading_mode_bypass = '2'
        elif level == '3':
            writing_mode = '1'
            reading_mode = '1'
            writing_mode_bypass = '1'
            reading_mode_bypass = '1'
        else:
            writing_mode = '1'
            reading_mode = '1'
            writing_mode_bypass = '2'
            reading_mode_bypass = '2'
        self.set_setting_value(__section__, 'bScanWriting', writing_mode)
        self.set_setting_value(__section__, 'bScanReading', reading_mode)
        self.set_setting_value(__section__, 'bScanWritingByPass', writing_mode_bypass)
        self.set_setting_value(__section__, 'bScanReadingByPass', reading_mode_bypass)
        return success

    when_to_scan = property(get_when_to_scan, set_when_to_scan)

    #	Scanning - What to Scan
    def get_what_to_scan(self, __section__='Default-Detection'):
        """
        Get what to scan
        Returns level and extension as a tupple:
        '1': All files
        '2': Default and specified file types
        '3': Default and specified file types with scan for macros
        '4': Specified file types only (Extension must be defined)
             -> To scan also all files with no extension add the extension ':::'.
        """
        level = self.get_setting_value(__section__, 'extensionMode')
        extensions = self.get_setting_value(__section__, 'szProgExts')
        return (level, extensions)

    def set_what_to_scan(self, level, extensions='', __section__='Default-Detection'):
        """
        Set what to scan
        Use level and extension as inputs:
        '1': All files
        '2': Default and specified file types
        '3': Default and specified file types with scan for macros
        '4': Specified file types only (Extension must be defined)
             -> To scan also all files with no extension add the extension ':::'.
        """
        if level not in ['1', '2', '3', '4']:
            raise ValueError('Level must be within ["1", "2", "3", "4"].')
        if level == '4' and len(extensions) < 3:
            raise ValueError('Extensions list, comma separated, must be defined for this level.')
        self.set_setting_value(__section__, 'extensionMode', level)
        self.set_setting_value(__section__, 'szProgExts', extensions)
        return True

    what_to_scan = property(get_what_to_scan, set_what_to_scan)

    #	Scanning - What to Scan
    def get_scan_network_drives(self, __section__='Default-Detection'):
        """
        Get On network drives
        """
        return self.get_setting_value(__section__, 'bNetworkScanEnabled')

    def set_scan_network_drives(self, mode, __section__='Default-Detection'):
        """
        Set On network drives
        """
        return self.set_setting_value(__section__, 'bNetworkScanEnabled', mode)

    scan_network_drives = property(get_scan_network_drives, set_scan_network_drives)

    #	Scanning - What to Scan
    def get_scan_backups(self, __section__='Default-Detection'):
        """
        Get Opened for backups
        """
        return self.get_setting_value(__section__, 'bScanBackupReads')

    def set_scan_backups(self, mode, __section__='Default-Detection'):
        """
        Set Opened for backups
        """
        return self.set_setting_value(__section__, 'bScanBackupReads', mode)

    scan_backups = property(get_scan_backups, set_scan_backups)

    #	Scanning - What to Scan
    def get_scan_archives(self, __section__='Default-Detection'):
        """
        Get Compressed archive files
        """
        return self.get_setting_value(__section__, 'bScanArchives')

    def set_scan_archives(self, mode, __section__='Default-Detection'):
        """
        Set Compressed archive files
        """
        return self.set_setting_value(__section__, 'bScanArchives', mode)

    scan_archives = property(get_scan_archives, set_scan_archives)

    #	Scanning - What to Scan
    def get_scan_mime(self, __section__='Default-Detection'):
        """
        Get Compressed MIME-encoded files
        """
        return self.get_setting_value(__section__, 'bScanMime')

    def set_scan_mime(self, mode, __section__='Default-Detection'):
        """
        Set Compressed MIME-encoded files
        """
        return self.set_setting_value(__section__, 'bScanMime', mode)

    scan_mime = property(get_scan_mime, set_scan_mime)

    #	Scanning - Additional scan options
    def get_scan_pup(self, __section__='Default-Detection'):
        """
        Get Detect unwanted programs
        """
        return self.get_setting_value(__section__, 'bApplyNVP')

    def set_scan_pup(self, mode, __section__='Default-Detection'):
        """
        Set Detect unwanted programs
        """
        return self.set_setting_value(__section__, 'bApplyNVP', mode)

    scan_pup = property(get_scan_pup, set_scan_pup)

    #	Scanning - Additional scan options
    def get_scan_unknown_threats(self, __section__='Default-Detection'):
        """
        Get Detect unknown program threats
        """
        return self.get_setting_value(__section__, 'bUnknownProgramHeuristics')

    def set_scan_unknown_threats(self, mode, __section__='Default-Detection'):
        """
        Set Detect unknown program threats
        """
        return self.set_setting_value(__section__, 'bUnknownProgramHeuristics', mode)

    scan_unknown_threats = property(get_scan_unknown_threats, set_scan_unknown_threats)

    #	Scanning - Additional scan options
    def get_scan_unknown_macro(self, __section__='Default-Detection'):
        """
        Get Detect unknown macro threats
        """
        return self.get_setting_value(__section__, 'bUnknownMacroHeuristics')

    def set_scan_unknown_macro(self, mode, __section__='Default-Detection'):
        """
        Set Detect unknown macro threats
        """
        return self.set_setting_value(__section__, 'bUnknownMacroHeuristics', mode)

    scan_unknown_macro = property(get_scan_unknown_macro, set_scan_unknown_macro)

    # ---------------------- On-Access Policy - Standard ---------------------------
    #	Actions:
    def get_action_threat_first_response(self, __section__='Default-Detection'):
        """
        Get Action - Threat detection first response
        Return the value of the current level
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        """
        return self.get_setting_value(__section__, 'uAction')

    def set_action_threat_first_response(self, action, __section__='Default-Detection'):
        """
        Set Action - Threat detection first response
        Use the following value:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        """
        if action not in ['1', '2', '3']:
            raise ValueError('Action must be within ["1", "2", "3"].')
        return self.set_setting_value(__section__, 'uAction', action)

    action_threat_first_response = property(get_action_threat_first_response,
                                            set_action_threat_first_response)

    def get_action_threat_second_response(self, __section__='Default-Detection'):
        """
        Get Action - If first response fails:
        Secondary action must greater than the first one
        '2': Delete files
        '3': Deny access to files
        If first = '3' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section__, 'uSecAction')

    def set_action_threat_second_response(self, action, __section__='Default-Detection'):
        """
        Set Action - If first response fails:
        Secondary action must greater than the first one
        '2': Delete files
        '3': Deny access to files
        If first = '3' -> No secondary options available for this action.
        """
        if action not in ['2', '3']:
            raise ValueError('Action must be within ["2", "3"].')
        first_action = int(self.get_setting_value(__section__, 'uAction'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section__, 'uSecAction', action)

    action_threat_second_response = property(get_action_threat_second_response,
                                             set_action_threat_second_response)

    def get_action_pup_first_response(self, __section__='Default-Detection'):
        """
        Get Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        """
        return self.get_setting_value(__section__, 'uAction_Program')

    def set_action_pup_first_response(self, action, __section__='Default-Detection'):
        """
        Set Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        """
        if action not in ['1', '2', '3', '4']:
            raise ValueError('Action must be within ["1", "2", "3", "4"].')
        return self.set_setting_value(__section__, 'uAction_Program', action)

    action_pup_first_response = property(get_action_pup_first_response,
                                         set_action_pup_first_response)

    def get_action_pup_second_response(self, __section__='Default-Detection'):
        """
        Get Action - If first response fails:
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        If first >= '3' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section__, 'uSecAction_Program')

    def set_action_pup_second_response(self, action, __section__='Default-Detection'):
        """
        Set Action - If first response fails:
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        If first >= '3' -> No secondary options available for this action.
        """
        if action not in ['2', '3', '4']:
            raise ValueError('Action must be within ["2", "3", "4"].')
        first_action = int(self.get_setting_value(__section__, 'uAction_Program'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section__, 'uSecAction_Program', action)

    action_pup_second_response = property(get_action_pup_second_response,
                                          set_action_pup_second_response)

    # ---------------------- On-Access Policy - Standard ---------------------------
    #   Hidden setting
    def __get_action_on_error(self, __section__='Default-Detection'):
        """
        Get Hidden setting - Action on scanning error
        Default value set to: Allow access to files
        """
        return self.get_setting_value(__section__, 'uScanErrorAction')

    def __get_action_on_timeout(self, __section__='Default-Detection'):
        """
        Get Hidden setting - Action on scanning time-out
        Default value set to: Allow access to files
        """
        return self.get_setting_value(__section__, 'uTimeOutAction')

    # ---------------------- On-Access Policy - Standard ---------------------------
    #	Exclusions - Standard
    def get_exclusion_list(self, __section__='Default-Detection_Exclusions'):
        """
        Get exclusions list
        Return a list that can be used as ProcessList object.
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(__section__))
        if section_obj is not None:
            setting_obj = section_obj.find('Setting[@name="dwExclusionCount"]')
            max_rows = int(setting_obj.get('value'))
            if max_rows > 0:
                table = list()
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="ExcludedItem_{}"]'.format(row))
                    row_values = setting_obj.get('value').split('|')
                    table.append(row_values)
        return table

    def set_exclusion_list(self, table, __section__='Default-Detection_Exclusions'):
        """
        Set exclusions list
        Use a list or a ProcessList object as input
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(__section__))
        if section_obj is not None:
            success = True
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name=__section__)
            if len(table) > 0:
                et.SubElement(section_obj, 'Setting',
                              {"name":'dwExclusionCount', "value":str(len(table))})
                for index, row in enumerate(table):
                    exclusion = row[0] + '|' + row[1] + '|' + row[2] + '|' + row[3]
                    et.SubElement(section_obj, 'Setting',
                                  {"name":'ExcludedItem_{}'.format(index), "value":exclusion})
            else:
                et.SubElement(section_obj, 'Setting',
                              {"name":'dwExclusionCount', "value":'0'})
        return success

    exclusion_list = property(get_exclusion_list, set_exclusion_list)

    def get_overwrite_exclusions(self, __section__='Default-Detection_Exclusions'):
        """
        Get Exclusions - Overwrite exclusions configured on the client
        """
        return self.get_setting_value(__section__, 'bOverwriteExclusions')

    def set_overwrite_exclusions(self, mode, __section__='Default-Detection_Exclusions'):
        """
        Set Exclusions - Overwrite exclusions configured on the client
        """
        return self.set_setting_value(__section__, 'bOverwriteExclusions', mode)

    overwrite_exclusions = property(get_overwrite_exclusions, set_overwrite_exclusions)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    # Process Settings:
    #	Process Type: High Risk
    def get_when_to_scan_hr(self):
        """
        Get When to scan, Reading/Writing for High Risk process.
        Read get_when_to_scan for more help.
        """
        return self.get_when_to_scan('HighRisk-Detection')

    def set_when_to_scan_hr(self, level):
        """
        Set When to scan, Reading/Writing for High Risk process.
        Read set_when_to_scan for more help.
        """
        return self.set_when_to_scan(level, 'HighRisk-Detection')

    when_to_scan_hr = property(get_when_to_scan_hr, set_when_to_scan_hr)

    #   Scanning - What to Scan - High Risk
    def get_what_to_scan_hr(self):
        """
        Get what to scan for High Risk process.
        """
        return self.get_what_to_scan('HighRisk-Detection')

    def set_what_to_scan_hr(self, level, extensions=''):
        """
        Set what to scan for High Risk process.
        """
        return self.set_what_to_scan(level, extensions, 'HighRisk-Detection')

    what_to_scan_hr = property(get_what_to_scan_hr, set_what_to_scan_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_network_drives_hr(self, __section__='Default-Detection'):
        """
        Get On network drives for High Risk process.
        """
        return self.get_scan_network_drives('HighRisk-Detection')

    def set_scan_network_drives_hr(self, mode):
        """
        Set On network drives for High Risk process.
        """
        return self.set_scan_network_drives(mode, 'HighRisk-Detection')

    scan_network_drives_hr = property(get_scan_network_drives_hr, set_scan_network_drives_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_backups_hr(self):
        """
        Get Opened for backups for High Risk process.
        """
        return self.get_scan_backups('HighRisk-Detection')

    def set_scan_backups_hr(self, mode):
        """
        Set Opened for backups for High Risk process.
        """
        return self.set_scan_backups(mode, 'HighRisk-Detection')

    scan_backups_hr = property(get_scan_backups_hr, set_scan_backups_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_archives_hr(self):
        """
        Get Compressed archive files for High Risk process.
        """
        return self.get_scan_archives('HighRisk-Detection')

    def set_scan_archives_hr(self, mode):
        """
        Set Compressed archive files for High Risk process.
        """
        return self.set_scan_archives(mode, 'HighRisk-Detection')

    scan_archives_hr = property(get_scan_archives_hr, set_scan_archives_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_mime_hr(self):
        """
        Get Compressed MIME-encoded files for High Risk process.
        """
        return self.get_scan_mime('HighRisk-Detection')

    def set_scan_mime_hr(self, mode):
        """
        Set Compressed MIME-encoded files for High Risk process.
        """
        return self.set_scan_mime(mode, 'HighRisk-Detection')

    scan_mime_hr = property(get_scan_mime_hr, set_scan_mime_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_pup_hr(self):
        """
        Get Detect unwanted programs for High Risk process.
        """
        return self.get_scan_pup('HighRisk-Detection')

    def set_scan_pup_hr(self, mode):
        """
        Set Detect unwanted programs for High Risk process.
        """
        return self.set_scan_pup(mode, 'HighRisk-Detection')

    scan_pup_hr = property(get_scan_pup_hr, set_scan_pup_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_unknown_threats_hr(self):
        """
        Get Detect unknown program threats for High Risk process.
        """
        return self.get_scan_unknown_threats('HighRisk-Detection')

    def set_scan_unknown_threats_hr(self, mode):
        """
        Set Detect unknown program threats for High Risk process.
        """
        return self.set_scan_unknown_threats(mode, 'HighRisk-Detection')

    scan_unknown_threats_hr = property(get_scan_unknown_threats_hr, set_scan_unknown_threats_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_unknown_macro_hr(self):
        """
        Get Detect unknown macro threats for High Risk process.
        """
        return self.get_scan_unknown_macro('HighRisk-Detection')

    def set_scan_unknown_macro_hr(self, mode):
        """
        Set Detect unknown macro threats for High Risk process.
        """
        return self.set_scan_unknown_macro(mode, 'HighRisk-Detection')

    scan_unknown_macro_hr = property(get_scan_unknown_macro_hr, set_scan_unknown_macro_hr)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #	Actions:
    def get_action_threat_first_response_hr(self):
        """
        Get Action - Threat detection first response for High Risk process.
        """
        return self.get_action_threat_first_response('HighRisk-Detection')

    def set_action_threat_first_response_hr(self, action):
        """
        Set Action - Threat detection first response for High Risk process.
        """
        return self.set_action_threat_first_response(action, 'HighRisk-Detection')

    action_threat_first_response_hr = property(get_action_threat_first_response_hr,
                                            set_action_threat_first_response_hr)

    def get_action_threat_second_response_hr(self):
        """
        Get Action - If first response fails for High Risk process.
        """
        return self.get_action_threat_second_response('HighRisk-Detection')

    def set_action_threat_second_response_hr(self, action):
        """
        Set Action - If first response fails for High Risk process.
        """
        return self.set_action_threat_second_response(action, 'HighRisk-Detection')

    action_threat_second_response_hr = property(get_action_threat_second_response_hr,
                                             set_action_threat_second_response_hr)

    def get_action_pup_first_response_hr(self):
        """
        Get Action - Unwanted program first response for High Risk process.
        """
        return self.get_action_pup_first_response('HighRisk-Detection')

    def set_action_pup_first_response_hr(self, action):
        """
        Set Action - Unwanted program first response for High Risk process.
        """
        return self.set_action_pup_first_response(action, 'HighRisk-Detection')

    action_pup_first_response_hr = property(get_action_pup_first_response_hr,
                                         set_action_pup_first_response_hr)

    def get_action_pup_second_response_hr(self):
        """
        Get Action - If first response fails for High Risk process.
        """
        return self.get_action_pup_second_response('HighRisk-Detection')

    def set_action_pup_second_response_hr(self, action):
        """
        Set Action - If first response fails for High Risk process.
        """
        return self.set_action_pup_second_response(action, 'HighRisk-Detection')

    action_pup_second_response_hr = property(get_action_pup_second_response_hr,
                                          set_action_pup_second_response_hr)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #   Hidden setting
    def __get_action_on_error_hr(self):
        """
        Get Hidden setting - Action on scanning error for High Risk process.
        """
        return self.__get_action_on_error('HighRisk-Detection')

    def __get_action_on_timeout_hr(self):
        """
        Get Hidden setting - Action on scanning time-out for High Risk process.
        """
        return self.__get_action_on_timeout('HighRisk-Detection')

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #	Exclusions - High Risk
    def get_exclusion_list_hr(self):
        """
        Get exclusions list for High Risk process.
        """
        return self.get_exclusion_list('HighRisk-Detection_Exclusions')

    def set_exclusion_list_hr(self, table):
        """
        Set exclusions list for High Risk process.
        """
        return self.set_exclusion_list(table, 'HighRisk-Detection_Exclusions')

    exclusion_list_hr = property(get_exclusion_list_hr, set_exclusion_list_hr)

    def get_overwrite_exclusions_hr(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client for High-Risk process
        """
        return self.get_overwrite_exclusions('HighRisk-Detection_Exclusions')

    def set_overwrite_exclusions_hr(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client for High-Risk process
        """
        return self.set_overwrite_exclusions(mode, 'HighRisk-Detection_Exclusions')

    overwrite_exclusions_hr = property(get_overwrite_exclusions_hr, set_overwrite_exclusions_hr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    # Process Settings:
    #	Process Type: Low Risk
    def get_when_to_scan_lr(self):
        """
        Get When to scan, Reading/Writing for Low Risk process.
        Read get_when_to_scan for more help.
        """
        return self.get_when_to_scan('LowRisk-Detection')

    def set_when_to_scan_lr(self, level):
        """
        Set When to scan, Reading/Writing for Low Risk process.
        Read set_when_to_scan for more help.
        """
        return self.set_when_to_scan(level, 'LowRisk-Detection')

    when_to_scan_lr = property(get_when_to_scan_lr, set_when_to_scan_lr)

    #   Scanning - What to Scan - Low Risk
    def get_what_to_scan_lr(self):
        """
        Get what to scan for Low Risk process.
        """
        return self.get_what_to_scan('LowRisk-Detection')

    def set_what_to_scan_lr(self, level, extensions=''):
        """
        Set what to scan for Low Risk process.
        """
        return self.set_what_to_scan(level, extensions, 'LowRisk-Detection')

    what_to_scan_lr = property(get_what_to_scan_lr, set_what_to_scan_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_network_drives_lr(self, __section__='Default-Detection'):
        """
        Get On network drives for Low Risk process.
        """
        return self.get_scan_network_drives('LowRisk-Detection')

    def set_scan_network_drives_lr(self, mode):
        """
        Set On network drives for Low Risk process.
        """
        return self.set_scan_network_drives(mode, 'LowRisk-Detection')

    scan_network_drives_lr = property(get_scan_network_drives_lr, set_scan_network_drives_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_backups_lr(self):
        """
        Get Opened for backups for Low Risk process.
        """
        return self.get_scan_backups('LowRisk-Detection')

    def set_scan_backups_lr(self, mode):
        """
        Set Opened for backups for Low Risk process.
        """
        return self.set_scan_backups(mode, 'LowRisk-Detection')

    scan_backups_lr = property(get_scan_backups_lr, set_scan_backups_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_archives_lr(self):
        """
        Get Compressed archive files for Low Risk process.
        """
        return self.get_scan_archives('LowRisk-Detection')

    def set_scan_archives_lr(self, mode):
        """
        Set Compressed archive files for Low Risk process.
        """
        return self.set_scan_archives(mode, 'LowRisk-Detection')

    scan_archives_lr = property(get_scan_archives_lr, set_scan_archives_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_mime_lr(self):
        """
        Get Compressed MIME-encoded files for Low Risk process.
        """
        return self.get_scan_mime('LowRisk-Detection')

    def set_scan_mime_lr(self, mode):
        """
        Set Compressed MIME-encoded files for Low Risk process.
        """
        return self.set_scan_mime(mode, 'LowRisk-Detection')

    scan_mime_lr = property(get_scan_mime_lr, set_scan_mime_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_pup_lr(self):
        """
        Get Detect unwanted programs for Low Risk process.
        """
        return self.get_scan_pup('LowRisk-Detection')

    def set_scan_pup_lr(self, mode):
        """
        Set Detect unwanted programs for Low Risk process.
        """
        return self.set_scan_pup(mode, 'LowRisk-Detection')

    scan_pup_lr = property(get_scan_pup_lr, set_scan_pup_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_unknown_threats_lr(self):
        """
        Get Detect unknown program threats for Low Risk process.
        """
        return self.get_scan_unknown_threats('LowRisk-Detection')

    def set_scan_unknown_threats_lr(self, mode):
        """
        Set Detect unknown program threats for Low Risk process.
        """
        return self.set_scan_unknown_threats(mode, 'LowRisk-Detection')

    scan_unknown_threats_lr = property(get_scan_unknown_threats_lr, set_scan_unknown_threats_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_unknown_macro_lr(self):
        """
        Get Detect unknown macro threats for Low Risk process.
        """
        return self.get_scan_unknown_macro('LowRisk-Detection')

    def set_scan_unknown_macro_lr(self, mode):
        """
        Set Detect unknown macro threats for Low Risk process.
        """
        return self.set_scan_unknown_macro(mode, 'LowRisk-Detection')

    scan_unknown_macro_lr = property(get_scan_unknown_macro_lr, set_scan_unknown_macro_lr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #	Actions:
    def get_action_threat_first_response_lr(self):
        """
        Get Action - Threat detection first response for Low Risk process.
        """
        return self.get_action_threat_first_response('LowRisk-Detection')

    def set_action_threat_first_response_lr(self, action):
        """
        Set Action - Threat detection first response for Low Risk process.
        """
        return self.set_action_threat_first_response(action, 'LowRisk-Detection')

    action_threat_first_response_lr = property(get_action_threat_first_response_lr,
                                            set_action_threat_first_response_lr)

    def get_action_threat_second_response_lr(self):
        """
        Get Action - If first response fails for Low Risk process.
        """
        return self.get_action_threat_second_response('LowRisk-Detection')

    def set_action_threat_second_response_lr(self, action):
        """
        Set Action - If first response fails for Low Risk process.
        """
        return self.set_action_threat_second_response(action, 'LowRisk-Detection')

    action_threat_second_response_lr = property(get_action_threat_second_response_lr,
                                             set_action_threat_second_response_lr)

    def get_action_pup_first_response_lr(self):
        """
        Get Action - Unwanted program first response for Low Risk process.
        """
        return self.get_action_pup_first_response('LowRisk-Detection')

    def set_action_pup_first_response_lr(self, action):
        """
        Set Action - Unwanted program first response for Low Risk process.
        """
        return self.set_action_pup_first_response(action, 'LowRisk-Detection')

    action_pup_first_response_lr = property(get_action_pup_first_response_lr,
                                         set_action_pup_first_response_lr)

    def get_action_pup_second_response_lr(self):
        """
        Get Action - If first response fails for Low Risk process.
        """
        return self.get_action_pup_second_response('LowRisk-Detection')

    def set_action_pup_second_response_lr(self, action):
        """
        Set Action - If first response fails for Low Risk process.
        """
        return self.set_action_pup_second_response(action, 'LowRisk-Detection')

    action_pup_second_response_lr = property(get_action_pup_second_response_lr,
                                          set_action_pup_second_response_lr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #   Hidden setting
    def __get_action_on_error_lr(self):
        """
        Get Hidden setting - Action on scanning error for Low Risk process.
        """
        return self.__get_action_on_error('LowRisk-Detection')

    def __get_action_on_timeout_lr(self):
        """
        Get Hidden setting - Action on scanning time-out for Low Risk process.
        """
        return self.__get_action_on_timeout('LowRisk-Detection')

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #	Exclusions - Low Risk
    def get_exclusion_list_lr(self):
        """
        Get exclusions list for Low Risk process.
        """
        return self.get_exclusion_list('LowRisk-Detection_Exclusions')

    def set_exclusion_list_lr(self, table):
        """
        Set exclusions list for Low Risk process.
        """
        return self.set_exclusion_list(table, 'LowRisk-Detection_Exclusions')

    exclusion_list_lr = property(get_exclusion_list_lr, set_exclusion_list_lr)

    def get_overwrite_exclusions_lr(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client for Low Risk process
        """
        return self.get_overwrite_exclusions('LowRisk-Detection_Exclusions')

    def set_overwrite_exclusions_lr(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client for Low Risk process
        """
        return self.set_overwrite_exclusions(mode, 'LowRisk-Detection_Exclusions')

    overwrite_exclusions_lr = property(get_overwrite_exclusions_lr, set_overwrite_exclusions_lr)

    # ------------------------------ On-Access Policy ------------------------------
    # ScriptScan:
    def get_script_scan(self):
        """
        Get Enable ScriptScan
        """
        return self.get_setting_value('ScriptScan', 'scriptScanEnabled')

    def set_script_scan(self, mode):
        """
        Set Enable ScriptScan
        """
        return self.set_setting_value('ScriptScan', 'scriptScanEnabled', mode)

    script_scan = property(get_script_scan, set_script_scan)

    #	Exclude these URLs or partial URLs:
    def get_script_scan_exclusions(self):
        """
        Get Excluded URLs
        Return a list or an URLList object
        """
        excluded_urls = list()
        max_rows = int(self.get_setting_value('ScriptScanURLExclItems',
                                              'dwScriptScanURLExclItemCount'))
        for row in range(max_rows):
            excluded_urls.append(self.get_setting_value('ScriptScanURLExclItems',
                                                        'ScriptScanExclusionURL_{}'.format(row)))
        return excluded_urls

    def set_script_scan_exclusions(self, excluded_urls):
        """
        Set Excluded URLs
        Use URLList object as input
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="ScriptScanURLExclItems"]')
        if section_obj is not None:
            success = True
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name='ScriptScanURLExclItems')
            et.SubElement(section_obj, 'Setting',
                          {"name":'dwScriptScanURLExclItemCount', "value":str(len(excluded_urls))})
            # Determine if there are some excluded urls
            if len(excluded_urls) > 0:
                for index, url in enumerate(excluded_urls):
                    et.SubElement(section_obj, 'Setting',
                                  {"name":'ScriptScanExclusionURL_{}'.format(index), "value":url})
        return success

    script_scan_exclusions = property(get_script_scan_exclusions, set_script_scan_exclusions)

class OASProcessList:
    """
    The OASProcessList class can be used to edit the list of process.
    All process names are associated to a risk level: Low or High.
    """

    def __init__(self, process_list = list()):
        self.proc_list = process_list

    def __repr__(self):
        return '<OASProcessList which contains {} process(s)>'.format(len(self.proc_list))

    def __str__(self):
        txt = '| {0:40}| {1:13}|\n'.format('Process Name', 'Process Type')
        txt += '|:----------------------------------------|:-------------|'
        for row in self.proc_list:
            txt += '\n| {0:40}| {1:13}|'.format(row[0], row[1])
        return txt

    def add(self, process_name, process_type):
        """
        Add a process name of process type within the process list.
        :process_name: The name of the process.
        :process_type: 'Low Risk' or 'High Risk' value.
        """
        success = False
        if process_type not in ['Low Risk', 'High Risk']:
            raise ValueError('Process Type unknown. Value must be "Low Risk" or "High Risk".')
        if not self.contains(process_name):
            row = []
            row.append(process_name)
            row.append(process_type)
            self.proc_list.append(row)
            success = True
        return success

    def add_low_risk(self, process_name):
        """
        Add a low risk process name within the process list.
        :process_name: The name of the process.
        """
        return self.add(process_name, 'Low Risk')

    def add_high_risk(self, process_name):
        """
        Add a high risk process name within the process list.
        :process_name: The name of the process.
        """
        return self.add(process_name, 'High Risk')

    def remove(self, process_name):
        """
        Remove a process name of the process list.
        :process_name: The name of the process.
        """
        table = [row for row in self.proc_list if row[0] != process_name]
        self.proc_list = table
        return True

    def contains(self, process_name):
        """
        Return True if the process list contains a process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list if row[0] == process_name]
        return len(search) >= 1

    def contains_low_risk(self, process_name):
        """
        Return True if the process list contains a low risk process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list
                  if row[0] == process_name and row[1] == 'Low Risk']
        return len(search) >= 1

    def contains_high_risk(self, process_name):
        """
        Return True if the process list contains a high risk process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list
                  if row[0] == process_name and row[1] == 'High Risk']
        return len(search) >= 1

class OASExclusionList(ExclusionList):
    pass

class OASURLList:
    """
    The OASURLList class can be used to edit the list of excluded URL.
    """

    def __init__(self, excluded_urls = list()):
        self.url_list = excluded_urls

    def __repr__(self):
        return '<OASURLList which contains {} exclusion(s)>'.format(len(self.url_list))

    def __str__(self):
        txt = '| {0:40}|\n'.format('Excluded URL')
        txt += '|:----------------------------------------|'
        for row in self.url_list:
            txt += '\n| {0:40}|'.format(row)
        return txt

    def add(self, url):
        """
        Add an url in the excluded url list.
        :url: The URL to be added.
        """
        success = False
        if not self.contains(url):
            self.url_list.append(url)
            success = True
        return success

    def remove(self, url):
        """
        Remove an url of the excluded url list.
        :url: The URL to be removed.
        """
        self.url_list.remove(url)
        return True

    def contains(self, url):
        """
        Return True if the excluded url list contains an url.
        :url: The URL to look for.
        """
        search = [row for row in self.url_list if row == url]
        return len(search) >= 1
