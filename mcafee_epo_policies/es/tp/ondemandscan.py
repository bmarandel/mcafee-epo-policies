# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESTPPolicyOnDemandScan.
"""

import xml.etree.ElementTree as et
from ...policies import Policy
from .exclusions import ExclusionList

class ESTPPolicyOnDemandScan(Policy):
    """
    The ESTPPolicyOnDemandScan class can be used to edit the Endpoint Security
    Threat Prevention policy: On-Demand Scan.

    The class is used to configure the three types of on-demand scan:
    - Full Scan
    - Quick Scan
    - Right-click Scan

    Note: For Right-click scans, you do not have to set the scan locations. The
          location is defined by the object where the user has right-click.
    """

    def __init__(self, policy_from_estppolicies=None):
        super(ESTPPolicyOnDemandScan, self).__init__(policy_from_estppolicies)
        if policy_from_estppolicies is not None:
            if self.get_type() != 'EAM_OnDemandScan_Policies':
                raise ValueError('Wrong policy! Policy type must be "EAM_OnDemandScan_Policies".')

    def __repr__(self):
        return 'ESTPPolicyOnDemandScan()'

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # What to Scan:
    #   Boot sectors
    def get_fs_boot_sectors(self, __section='FS'):
        """
        Get Scan boot sectors for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bScanBootSectors')

    def set_fs_boot_sectors(self, mode, __section='FS'):
        """
        Set Scan boot sectors for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bScanBootSectors', mode)

    fs_boot_sectors = property(get_fs_boot_sectors, set_fs_boot_sectors)

    #   Files that have been migrated to storage
    def get_fs_files_to_storage(self, __section='FS'):
        """
        Get Files migrated to storage for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bScanFilesMigratedToStorage')

    def set_fs_files_to_storage(self, mode, __section='FS'):
        """
        Set Files migrated to storage for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions',
                                      'bScanFilesMigratedToStorage', mode)

    fs_files_to_storage = property(get_fs_files_to_storage, set_fs_files_to_storage)

    #   Compressed MIME-encoded files
    def get_fs_mime(self, __section='FS'):
        """
        Get Compressed MIME-encoded files for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bScanMime')

    def set_fs_mime(self, mode, __section='FS'):
        """
        Set Compressed MIME-encoded files for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bScanMime', mode)

    fs_mime = property(get_fs_mime, set_fs_mime)

    #   Compressed archives files
    def get_fs_archives(self, __section='FS'):
        """
        Get Compressed archive files for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bScanArchives')

    def set_fs_archives(self, mode, __section='FS'):
        """
        Set Compressed archive files for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bScanArchives', mode)

    fs_archives = property(get_fs_archives, set_fs_archives)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Additional Scan Options:
    #   Detect unwanted programs
    def get_fs_pup(self, __section='FS'):
        """
        Get Detect unwanted programs for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bDetectUnwantedPrograms')

    def set_fs_pup(self, mode, __section='FS'):
        """
        Set Detect unwanted programs for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bDetectUnwantedPrograms', mode)

    fs_pup = property(get_fs_pup, set_fs_pup)

    #   Detect unknown program threats
    def get_fs_unknown_threats(self, __section='FS'):
        """
        Get Detect unknown program threats for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bUnknownProgramHeuristics')

    def set_fs_unknown_threats(self, mode, __section='FS'):
        """
        Set Detect unknown program threats for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bUnknownProgramHeuristics', mode)

    fs_unknown_threats = property(get_fs_unknown_threats, set_fs_unknown_threats)

    #   Detect unknown macro threats
    def get_fs_unknown_macro(self, __section='FS'):
        """
        Get Detect unknown macro threats for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bUnknownMacroHeuristics')

    def set_fs_unknown_macro(self, mode, __section='FS'):
        """
        Set Detect unknown macro threats for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bUnknownMacroHeuristics', mode)

    fs_unknown_macro = property(get_fs_unknown_macro, set_fs_unknown_macro)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Scan Locations:
    #   Scan subfolders
    def get_fs_subfolders(self, __section='FS'):
        """
        Get Scan subfolders for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'bScanSubDirs')

    def set_fs_subfolders(self, mode, __section='FS'):
        """
        Set Scan subfolders for Full Scan
        """
        return self.set_setting_value(__section + '_ScanOptions', 'bScanSubDirs', mode)

    fs_subfolders = property(get_fs_subfolders, set_fs_subfolders)

    #   Specify locations
    def get_fs_locations(self, __section='FS'):
        """
        Get scan locations for Full Scan
        Possible locations are defined like that:
        'SpecialScanForRootkits':   'Memory for rootkits'
        'SpecialMemory':            'Running processes'
        'SpecialCritical':          'Registered files'
        'My Computer':              'My computer'
        'LocalDrives':              'All local drives'
        'All fixed disks':          'All fixed drives'
        'All removable media':      'All removable drives'
        'All Network drives':       'All mapped drives'
        'HomeDir':                  'Home folder'
        'ProfileDir':               'User profile folder'
        'WinDir':                   'Windows folder'
        'ProgramFilesDir':          'Program files folder'
        'TempDir':                  'Temp folder'
        'SpecialRecycleName':       'Recycle bin'
        'SpecialRegistry':          'Registry'
        Note for 'File or folder' simply use the full path directly.
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}_ScanOptions"]'.format(__section))
        if section_obj is not None:
            setting_obj = section_obj.find('Setting[@name="dwScanItemCount"]')
            max_rows = int(setting_obj.get('value'))
            if max_rows > 0:
                table = list()
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="szScanItem{}"]'.format(row))
                    row_value = setting_obj.get('value')
                    table.append(row_value)
        return table

    def set_fs_locations(self, table, __section='FS'):
        """
        Set scan locations for Full Scan
        Possible locations are defined like that:
        'SpecialScanForRootkits':   'Memory for rootkits'
        'SpecialMemory':            'Running processes'
        'SpecialCritical':          'Registered files'
        'My Computer':              'My computer'
        'LocalDrives':              'All local drives'
        'All fixed disks':          'All fixed drives'
        'All removable media':      'All removable drives'
        'All Network drives':       'All mapped drives'
        'HomeDir':                  'Home folder'
        'ProfileDir':               'User profile folder'
        'WinDir':                   'Windows folder'
        'ProgramFilesDir':          'Program files folder'
        'TempDir':                  'Temp folder'
        'SpecialRecycleName':       'Recycle bin'
        'SpecialRegistry':          'Registry'
        Note for 'File or folder' simply use the full path directly.
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}_ScanOptions"]'.format(__section))
        if section_obj is not None:
            success = True
            # Get how many row already exist and remove the setting object
            setting_obj = section_obj.find('Setting[@name="dwScanItemCount"]')
            max_rows = int(setting_obj.get('value'))
            section_obj.remove(setting_obj)
            # Is there some items to remove?
            if max_rows > 0:
                # For each row find the object and remove it
                for i in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="szScanItem{}"]'.format(i))
                    section_obj.remove(setting_obj)
            # Is there some items to insert?
            if len(table) > 0:
                et.SubElement(section_obj, 'Setting',
                              {"name":'dwScanItemCount', "value":str(len(table))})
                for index, location in enumerate(table):
                    et.SubElement(section_obj, 'Setting',
                                  {"name":'szScanItem{}'.format(index), "value":location})
            else:
                et.SubElement(section_obj, 'Setting',
                              {"name":'dwScanItemCount', "value":'0'})
        return success

    fs_locations = property(get_fs_locations, set_fs_locations)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # File Types to Scan:
    #   All files
    #   Default and speciied file types
    #   Specified file types only
    def get_fs_file_types(self, __section='FS'):
        """
        Get File types to Scan for Full Scan
        Returns level and extensions as a tupple:
        '1': All files
        '2': Default and specified file types
        '3': Default and specified file types with scan for macros
        '4': Specified file types only (Extension must be defined)
             -> To scan also all files with no extension add the extension ':::'.
        """
        level = self.get_setting_value(__section + '_ScanOptions', 'ExtensionMode')
        extensions = self.get_setting_value(__section + '_ScanOptions', 'szProgExts')
        return (level, extensions)

    def set_fs_file_types(self, level, extensions='', __section='FS'):
        """
        Set File types to scan for Full Scan
        Use level and extensions as inputs:
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
        self.set_setting_value(__section + '_ScanOptions', 'ExtensionMode', level)
        self.set_setting_value(__section + '_ScanOptions', 'szProgExts', extensions)
        return True

    fs_file_types = property(get_fs_file_types, set_fs_file_types)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # McAfee GTI:
    #   Enable McAfee GTI / Sensitivity level
    #   0 = OFF         Gti().DISABLED
    #   1 = Very Low    Gti().VERY_LOW
    #   2 = Low         Gti().LOW
    #   3 = Medium      Gti().MEDIUM
    #   4 = High        Gti().HIGH
    #   5 = Very High   Gti().VERY_HIGH
    def get_fs_gti_level(self, __section='FS'):
        """
        Get the GTI level (Use Gti class from constants) for Full Scan
        """
        return self.get_setting_value(__section + '_ScanOptions', 'GTISensitivityLevel')

    def set_fs_gti_level(self, level, __section='FS'):
        """
        Set the GTI level (Use Gti class from constants) for Full Scan
        """
        if level not in ['0', '1', '2', '3', '4', '5']:
            raise ValueError('GTI sensitivity level must be within ["0", "1", "2", "3", "4", "5"].')
        return self.set_setting_value(__section + '_ScanOptions', 'GTISensitivityLevel', level)

    fs_gti_level = property(get_fs_gti_level, set_fs_gti_level)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Exclusions:
    #   Exclusions
    def get_fs_exclusion_list(self, __section='FS'):
        """
        Get exclusions list for Full Scan
        Return a list that can be used as ProcessList object.
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}_Exclusions"]'.format(__section))
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

    def set_fs_exclusion_list(self, table, __section='FS'):
        """
        Set exclusions list for Full Scan
        Use a list or a ProcessList object as input
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}_Exclusions"]'.format(__section))
        if section_obj is not None:
            success = True
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name=__section + '_Exclusions')
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

    fs_exclusion_list = property(get_fs_exclusion_list, set_fs_exclusion_list)

    #   Overwrite exclusions configured on the client
    def get_fs_overwrite_exclusions(self, __section='FS'):
        """
        Get Exclusions - Overwrite exclusions configured on the client
        """
        return self.get_setting_value(__section + '_Exclusions', 'bOverwriteExclusions')

    def set_fs_overwrite_exclusions(self, mode, __section='FS'):
        """
        Set Exclusions - Overwrite exclusions configured on the client
        """
        return self.set_setting_value(__section + '_Exclusions', 'bOverwriteExclusions', mode)

    fs_overwrite_exclusions = property(get_fs_overwrite_exclusions, set_fs_overwrite_exclusions)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Actions:
    #   Threat detection first response
    def get_fs_threat_first_response(self, __section='FS'):
        """
        Get Action - Threat detection first response for Full Scan
        Return the value of the current level
        '1': Clean files
        '2': Delete files
        '6': Continue scanning
        """
        return self.get_setting_value(__section + '_Remediation', 'uAction')

    def set_fs_threat_first_response(self, action, __section='FS'):
        """
        Set Action - Threat detection first response for Full Scan
        Use the following value:
        '1': Clean files
        '2': Delete files
        '6': Continue scanning
        """
        if action not in ['1', '2', '6']:
            raise ValueError('Action must be within ["1", "2", "6"].')
        return self.set_setting_value(__section + '_Remediation', 'uAction', action)

    fs_threat_first_response = property(get_fs_threat_first_response,
                                        set_fs_threat_first_response)

    #   If first response fails
    def get_fs_threat_second_response(self, __section='FS'):
        """
        Get Action - If first response fails for Full Scan
        Secondary action must greater than the first one
        '2': Delete files
        '6': Continue scanning
        If first = '6' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section + '_Remediation', 'uSecAction')

    def set_fs_threat_second_response(self, action, __section='FS'):
        """
        Set Action - If first response fails for Full Scan
        Secondary action must greater than the first one
        '2': Delete files
        '6': Continue scanning
        If first = '6' -> No secondary options available for this action.
        """
        if action not in ['2', '6']:
            raise ValueError('Action must be within ["2", "6"].')
        first_action = int(self.get_setting_value(__section + '_Remediation', 'uAction'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section + '_Remediation', 'uSecAction', action)

    fs_threat_second_response = property(get_fs_threat_second_response,
                                         set_fs_threat_second_response)

    #   Unwanted program first response
    def get_fs_pup_first_response(self, __section='FS'):
        """
        Get Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '6': Continue scanning
        """
        return self.get_setting_value(__section + '_Remediation', 'uAction_Program')

    def set_fs_pup_first_response(self, action, __section='FS'):
        """
        Set Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '6': Continue scanning
        """
        if action not in ['1', '2', '6']:
            raise ValueError('Action must be within ["1", "2", "6"].')
        return self.set_setting_value(__section + '_Remediation', 'uAction_Program', action)

    fs_pup_first_response = property(get_fs_pup_first_response,
                                     set_fs_pup_first_response)

    #   If first response fails
    def get_fs_pup_second_response(self, __section='FS'):
        """
        Get Action - If first response fails:
        '2':Delete files
        '6': Continue scanning
        If first >= '6' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section + '_Remediation', 'uSecAction_Program')

    def set_fs_pup_second_response(self, action, __section='FS'):
        """
        Set Action - If first response fails:
        '2':Delete files
        '6': Continue scanning
        If first >= '6' -> No secondary options available for this action.
        """
        if action not in ['2', '6']:
            raise ValueError('Action must be within ["2", "6"].')
        first_action = int(self.get_setting_value(__section + '_Remediation', 'uAction_Program'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section + '_Remediation', 'uSecAction_Program', action)

    fs_pup_second_response = property(get_fs_pup_second_response,
                                      set_fs_pup_second_response)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Scheduled Scan Options:
    #   Scan only when the system is idle or Scan anytime
    def get_fs_when_to_scan(self, __section='FS'):
        """
        Get Scheduled scan level for Full Scan
        '0': Scan anytime
        '1': Scan only when the system is idle
        """
        return self.get_setting_value(__section + '_Performance', 'bInteractiveUserIsIdle')

    def set_fs_when_to_scan(self, level, __section='FS'):
        """
        Set Scheduled scan level for Full Scan
        '0': Scan anytime
        '1': Scan only when the system is idle
        """
        return self.set_setting_value(__section + '_Performance', 'bInteractiveUserIsIdle', level)

    fs_when_to_scan = property(get_fs_when_to_scan, set_fs_when_to_scan)

    #   Scan only when the system is idle: User can resume paused scans
    def get_fs_resume_paused(self, __section='FS'):
        """
        Get Do not scan when the system is on battery power for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bResumePausedScans')

    def set_fs_resume_paused(self, mode, __section='FS'):
        """
        Get Do not scan when the system is on battery power for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bResumePausedScans', mode)

    fs_resume_paused = property(get_fs_resume_paused, set_fs_resume_paused)

    #   Scan anytime: User can defer scans
    def get_fs_user_defer(self, __section='FS'):
        """
        Get User can defer scan for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bPermitUserDefer')

    def set_fs_user_defer(self, mode, __section='FS'):
        """
        Set User can defer scan for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bPermitUserDefer', mode)

    fs_user_defer = property(get_fs_user_defer, set_fs_user_defer)

    #   Scan anytime: User can defer scans
    #      Maximum number of times user can defer for one hour
    def get_fs_user_defer_max(self, __section='FS'):
        """
        Get Maximum number of times user can defer for one hour for Full Scan
        """
        return int(self.get_setting_value(__section + '_Performance', 'uDeferTime'))

    def set_fs_user_defer_max(self, int_max, __section='FS'):
        """
        Set Maximum number of times user can defer for one hour for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'uDeferTime', str(int_max))

    fs_user_defer_max = property(get_fs_user_defer_max, set_fs_user_defer_max)

    #   Scan anytime: User can defer scans
    #      User message: McAfee Endpoint Security is about to scan your system.
    def get_fs_user_defer_msg(self, __section='FS'):
        """
        Get User defer message for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'szDeferMessage')

    def set_fs_user_defer_msg(self, message='McAfee Endpoint Security is about to scan your system.',
                              __section='FS'):
        """
        Set User defer message for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'szDeferMessage', message)

    fs_user_defer_msg = property(get_fs_user_defer_msg, set_fs_user_defer_msg)

    #   Scan anytime: User can defer scans
    #      Message duration (seconds)
    def get_fs_user_defer_msg_duration(self, __section='FS'):
        """
        Get User defer message duration (seconds) for Full Scan
        """
        return int(self.get_setting_value(__section + '_Performance', 'uMessageDuration'))

    def set_fs_user_defer_msg_duration(self, int_seconds, __section='FS'):
        """
        Set User defer message duration (seconds) for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'uMessageDuration', str(int_seconds))

    fs_user_defer_msg_duration = property(get_fs_user_defer_msg_duration,
                                          set_fs_user_defer_msg_duration)

    #   Scan anytime: User can pause and cancel scans
    def get_fs_user_pause_cancel(self, __section='FS'):
        """
        Get User can pause and cancel scans for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bPauseAndCancelScans')

    def set_fs_user_pause_cancel(self, mode, __section='FS'):
        """
        Set User can pause and cancel scans for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bPauseAndCancelScans', mode)

    fs_user_pause_cancel = property(get_fs_user_pause_cancel, set_fs_user_pause_cancel)

    #   Scan anytime: Do not scan when the system is in presentation mode
    def get_fs_not_in_presentation(self, __section='FS'):
        """
        Get Do not scan when the system is in presentation mode for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bDeferScanInFullScreen')

    def set_fs_not_in_presentation(self, mode, __section='FS'):
        """
        Get Do not scan when the system is in presentation mode for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bDeferScanInFullScreen', mode)

    fs_not_in_presentation = property(get_fs_not_in_presentation, set_fs_not_in_presentation)

    #   Do not scan when the system is on battery power
    def get_fs_not_on_battery(self, __section='FS'):
        """
        Get Do not scan when the system is on battery power for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bDeferScanOnBattery')

    def set_fs_not_on_battery(self, mode, __section='FS'):
        """
        Get Do not scan when the system is on battery power for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bDeferScanOnBattery', mode)

    fs_not_on_battery = property(get_fs_not_on_battery, set_fs_not_on_battery)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Performance:
    #   Use the scan cache
    def get_fs_use_cache(self, __section='FS'):
        """
        Get Use the scan cache for Full Scan
        """
        return self.get_setting_value(__section + '_Performance', 'bUseCache')

    def set_fs_use_cache(self, mode, __section='FS'):
        """
        Get Use the scan cache for Full Scan
        """
        return self.set_setting_value(__section + '_Performance', 'bUseCache', mode)

    fs_use_cache = property(get_fs_use_cache, set_fs_use_cache)

    # Performance:
    #    System utilization or Limit maximum CPU usage
    def get_fs_performance_level(self, __section='FS'):
        """
        Get Performance level for Full Scan
        '0': Limit maximum CPU usage
        '1': System utilization
        """
        return self.get_setting_value(__section + '_Performance', 'bSystemUtilization')

    def set_fs_performance_level(self, level, __section='FS'):
        """
        Set Performance level for Full Scan
        '0': Limit maximum CPU usage
        '1': System utilization
        """
        return self.set_setting_value(__section + '_Performace', 'bSystemUtilization', level)

    fs_performance_level = property(get_fs_performance_level, set_fs_performance_level)

    #   System utilization (Low, Below normal or Normal)
    def get_fs_perf_system_utilization(self, __section='FS'):
        """
        Get System utilization level for Full Scan
        '1': Low
        '2': Below normal
        '3': Normal
        """
        return self.get_setting_value(__section + '_Performance', 'SystemUtilization')

    def set_fs_perf_system_utilization(self, level, __section='FS'):
        """
        Set System utilization level for Full Scan
        '1': Low
        '2': Below normal
        '3': Normal
        """
        if level not in ['1', '2', '3']:
            raise ValueError('The level must be within ["1", "2", "3"].')
        return self.set_setting_value(__section + '_Performance', 'SystemUtilization', level)

    fs_perf_system_utilization = property(get_fs_perf_system_utilization, set_fs_perf_system_utilization)

    #   Limit maximum CPU usage (Available only when Scan anytime is selected) Percentage (25-99)
    def get_fs_perf_max_cpu(self, __section='FS'):
        """
        Get Limit maximum CPU usage for Full Scan
        This setting is available only when Scan anytime level is selected.
        The percentage is a value between 25 and 99.
        """
        return int(self.get_setting_value(__section + '_Performance', 'CPUPercentage'))

    def set_fs_perf_max_cpu(self, int_percentage, __section='FS'):
        """
        Set Limit maximum CPU usage for Full Scan
        This setting is available only when Scan anytime level is selected.
        The percentage is a value between 25 and 99.
        """
        if int_percentage not in range(25, 100):
            raise ValueError('The percentage must be within 25-99.')
        return self.set_setting_value(__section + '_Performance', 'CPUPercentage', str(int_percentage))

    fs_perf_max_cpu = property(get_fs_perf_max_cpu, set_fs_perf_max_cpu)

    # ------------------------------ On-Demand Policy - Full Scan ------------------------------
    # Account: Enter user account for scanning networks devices
    #   User name
    def get_fs_user_name(self, __section='FS'):
        """
        Get User name for scanning networks devices during Full Scan
        """
        return self.get_setting_value(__section + '_Account', 'szUserName')

    def set_fs_user_name(self, user_name, __section='FS'):
        """
        Set User name for scanning networks devices during Full Scan
        """
        return self.set_setting_value(__section + '_Account', 'szUserName', user_name)

    fs_user_name = property(get_fs_user_name, set_fs_user_name)

    #   Password
    def get_fs_user_password(self, __section='FS'):
        """
        Get Password for scanning network devices during Full Scan
        Note: It impossible to retreive the password in clear text as the
              encryption algorythme is not public
        """
        #return self.get_setting_value(__section + '_Account', 'szPassword')
        return '************'

    def set_fs_user_password(self, password, __section='FS'):
        """
        Set Password for scanning network devices during Full Scan
        Note: It impossible to definethe password in clear text as the
              encryption algorythme is not public
        """
        #return self.set_setting_value(__section + '_Account', 'szPassword', password)
        return False

    fs_user_password = property(get_fs_user_password, set_fs_user_password)

    #   Domain
    def get_fs_domain_name(self, __section='FS'):
        """
        Get Domain name for scanning networks devices during Full Scan
        """
        return self.get_setting_value(__section + '_Account', 'szDomainName')

    def set_fs_domain_name(self, domain_name, __section='FS'):
        """
        Set Domain name for scanning networks devices during Full Scan
        """
        return self.set_setting_value(__section + '_Account', 'szDomainName', domain_name)

    fs_domain_name = property(get_fs_domain_name, set_fs_domain_name)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # What to Scan:
    #   Boot sectors
    def get_qs_boot_sectors(self):
        """
        Get Scan boot sectors for Quick Scan
        """
        return self.get_fs_boot_sectors('QS')

    def set_qs_boot_sectors(self, mode):
        """
        Set Scan boot sectors for Quick Scan
        """
        return self.set_fs_boot_sectors(mode, 'QS')

    qs_boot_sectors = property(get_qs_boot_sectors, set_qs_boot_sectors)

    #   Files that have been migrated to storage
    def get_qs_files_to_storage(self):
        """
        Get Files migrated to storage for Quick Scan
        """
        return self.get_fs_files_to_storage('QS')

    def set_qs_files_to_storage(self, mode):
        """
        Set Files migrated to storage for Quick Scan
        """
        return self.set_fs_files_to_storage(mode, 'QS')

    qs_files_to_storage = property(get_qs_files_to_storage, set_qs_files_to_storage)

    #   Compressed MIME-encoded files
    def get_qs_mime(self):
        """
        Get Compressed MIME-encoded files for Quick Scan
        """
        return self.get_fs_mime('QS')

    def set_qs_mime(self, mode):
        """
        Set Compressed MIME-encoded files for Quick Scan
        """
        return self.set_fs_mime(mode, 'QS')

    qs_mime = property(get_qs_mime, set_qs_mime)

    #   Compressed archives files
    def get_qs_archives(self):
        """
        Get Compressed archive files for Quick Scan
        """
        return self.get_fs_archives('QS')

    def set_qs_archives(self, mode):
        """
        Set Compressed archive files for Quick Scan
        """
        return self.set_fs_archives(mode, 'QS')

    qs_archives = property(get_qs_archives, set_qs_archives)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Additional Scan Options:
    #   Detect unwanted programs
    def get_qs_pup(self):
        """
        Get Detect unwanted programs for Quick Scan
        """
        return self.get_fs_pup('QS')

    def set_qs_pup(self, mode):
        """
        Set Detect unwanted programs for Quick Scan
        """
        return self.set_fs_pup(mode, 'QS')

    qs_pup = property(get_qs_pup, set_qs_pup)

    #   Detect unknown program threats
    def get_qs_unknown_threats(self):
        """
        Get Detect unknown program threats for Quick Scan
        """
        return self.get_fs_unknown_threats('QS')

    def set_qs_unknown_threats(self, mode):
        """
        Set Detect unknown program threats for Quick Scan
        """
        return self.set_fs_unknown_threats(mode, 'QS')

    qs_unknown_threats = property(get_qs_unknown_threats, set_qs_unknown_threats)

    #   Detect unknown macro threats
    def get_qs_unknown_macro(self):
        """
        Get Detect unknown macro threats for Quick Scan
        """
        return self.get_fs_unknown_macro('QS')

    def set_qs_unknown_macro(self, mode):
        """
        Set Detect unknown macro threats for Quick Scan
        """
        return self.set_fs_unknown_macro(mode, 'QS')

    qs_unknown_macro = property(get_qs_unknown_macro, set_qs_unknown_macro)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Scan Locations:
    #   Scan subfolders
    def get_qs_subfolders(self):
        """
        Get Scan subfolders for Quick Scan
        """
        return self.get_fs_subfolders('QS')

    def set_qs_subfolders(self, mode):
        """
        Set Scan subfolders for Quick Scan
        """
        return self.set_fs_subfolders(mode, 'QS')

    qs_subfolders = property(get_qs_subfolders, set_qs_subfolders)

    #   Specify locations
    def get_qs_locations(self):
        """
        Get scan locations for Quick Scan
        """
        return self.get_fs_locations('QS')

    def set_qs_locations(self, table):
        """
        Set scan locations for Quick Scan
        """
        return self.set_fs_locations(table, 'QS')

    qs_locations = property(get_qs_locations, set_qs_locations)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # File Types to Scan:
    #   All files
    #   Default and speciied file types
    #   Specified file types only
    def get_qs_file_types(self):
        """
        Get File types to Scan for Quick Scan
        """
        return self.get_fs_file_types('QS')

    def set_qs_file_types(self, level, extensions=''):
        """
        Set File types to scan for Quick Scan
        """
        return self.set_fs_file_types(level, extensions, 'QS')

    qs_file_types = property(get_qs_file_types, set_qs_file_types)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # McAfee GTI:
    #   Enable McAfee GTI / Sensitivity level
    #   0 = OFF         Gti().DISABLED
    #   1 = Very Low    Gti().VERY_LOW
    #   2 = Low         Gti().LOW
    #   3 = Medium      Gti().MEDIUM
    #   4 = High        Gti().HIGH
    #   5 = Very High   Gti().VERY_HIGH
    def get_qs_gti_level(self):
        """
        Get the GTI level (Use Gti class from constants) for Quick Scan
        """
        return self.get_fs_gti_level('QS')

    def set_qs_gti_level(self, level):
        """
        Set the GTI level (Use Gti class from constants) for Quick Scan
        """
        return self.set_fs_gti_level(level, 'QS')

    qs_gti_level = property(get_qs_gti_level, set_qs_gti_level)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Exclusions:
    #   Exclusions
    def get_qs_exclusion_list(self):
        """
        Get exclusions list for Quick Scan
        Return a list that can be used as ProcessList object.
        """
        return self.get_fs_exclusion_list('QS')

    def set_qs_exclusion_list(self, table):
        """
        Set exclusions list for Quick Scan
        Use a list or a ProcessList object as input
        """
        return self.set_fs_exclusion_list(table, 'QS')

    qs_exclusion_list = property(get_qs_exclusion_list, set_qs_exclusion_list)

    #   Overwrite exclusions configured on the client
    def get_qs_overwrite_exclusions(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client
        """
        return self.get_fs_overwrite_exclusions('QS')

    def set_qs_overwrite_exclusions(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client
        """
        return self.set_fs_overwrite_exclusions(mode, 'QS')

    qs_overwrite_exclusions = property(get_qs_overwrite_exclusions, set_qs_overwrite_exclusions)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Actions:
    #   Threat detection first response
    def get_qs_threat_first_response(self):
        """
        Get Action - Threat detection first response for Quick Scan
        Return the value of the current level
        """
        return self.get_fs_threat_first_response('QS')

    def set_qs_threat_first_response(self, action):
        """
        Set Action - Threat detection first response for Quick Scan
        """
        return self.set_fs_threat_first_response(action, 'QS')

    qs_threat_first_response = property(get_qs_threat_first_response,
                                        set_qs_threat_first_response)

    #   If first response fails
    def get_qs_threat_second_response(self):
        """
        Get Action - If first response fails for Quick Scan
        Secondary action must greater than the first one
        """
        return self.get_fs_threat_second_response('QS')

    def set_qs_threat_second_response(self, action):
        """
        Set Action - If first response fails for Quick Scan
        Secondary action must greater than the first one
        """
        return self.set_fs_threat_second_response(action, 'QS')

    qs_threat_second_response = property(get_qs_threat_second_response,
                                         set_qs_threat_second_response)

    #   Unwanted program first response
    def get_qs_pup_first_response(self):
        """
        Get Action - Unwanted program first response:
        """
        return self.get_fs_pup_first_response('QS')

    def set_qs_pup_first_response(self, action):
        """
        Set Action - Unwanted program first response:
        """
        return self.set_fs_pup_first_response(action, 'QS')

    qs_pup_first_response = property(get_qs_pup_first_response,
                                     set_qs_pup_first_response)

    #   If first response fails
    def get_qs_pup_second_response(self):
        """
        Get Action - If first response fails:
        """
        return self.get_fs_pup_second_response('QS')

    def set_qs_pup_second_response(self, action):
        """
        Set Action - If first response fails:
        """
        return self.set_fs_pup_second_response(action, 'QS')

    qs_pup_second_response = property(get_qs_pup_second_response,
                                      set_qs_pup_second_response)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Scheduled Scan Options:
    #   Scan only when the system is idle or Scan anytime
    def get_qs_when_to_scan(self):
        """
        Get Scheduled scan level for Quick Scan
        """
        return self.get_fs_when_to_scan('QS')

    def set_qs_when_to_scan(self, level):
        """
        Set Scheduled scan level for Quick Scan
        """
        return self.set_fs_when_to_scan(level, 'QS')

    qs_when_to_scan = property(get_qs_when_to_scan, set_qs_when_to_scan)

    #   Scan only when the system is idle: User can resume paused scans
    def get_qs_resume_paused(self):
        """
        Get Do not scan when the system is on battery power for Quick Scan
        """
        return self.get_fs_resume_paused('QS')

    def set_qs_resume_paused(self, mode):
        """
        Get Do not scan when the system is on battery power for Quick Scan
        """
        return self.set_fs_resume_paused(mode, 'QS')

    qs_resume_paused = property(get_qs_resume_paused, set_qs_resume_paused)

    #   Scan anytime: User can defer scans
    def get_qs_user_defer(self):
        """
        Get User can defer scan for Quick Scan
        """
        return self.get_fs_user_defer('QS')

    def set_qs_user_defer(self, mode):
        """
        Set User can defer scan for Quick Scan
        """
        return self.set_fs_user_defer(mode, 'QS')

    qs_user_defer = property(get_qs_user_defer, set_qs_user_defer)

    #   Scan anytime: User can defer scans
    #      Maximum number of times user can defer for one hour
    def get_qs_user_defer_max(self):
        """
        Get Maximum number of times user can defer for one hour for Quick Scan
        """
        return self.get_fs_user_defer_max('QS')

    def set_qs_user_defer_max(self, int_max):
        """
        Set Maximum number of times user can defer for one hour for Quick Scan
        """
        return self.set_fs_user_defer_max(int_max, 'QS')

    qs_user_defer_max = property(get_qs_user_defer_max, set_qs_user_defer_max)

    #   Scan anytime: User can defer scans
    #      User message: McAfee Endpoint Security is about to scan your system.
    def get_qs_user_defer_msg(self):
        """
        Get User defer message for Quick Scan
        """
        return self.get_fs_user_defer_msg('QS')

    def set_qs_user_defer_msg(self, message):
        """
        Set User defer message for Quick Scan
        """
        return self.set_fs_user_defer_msg(message, 'QS')

    qs_user_defer_msg = property(get_qs_user_defer_msg, set_qs_user_defer_msg)

    #   Scan anytime: User can defer scans
    #      Message duration (seconds)
    def get_qs_user_defer_msg_duration(self):
        """
        Get User defer message duration (seconds) for Quick Scan
        """
        return self.get_fs_user_defer_msg_duration('QS')

    def set_qs_user_defer_msg_duration(self, int_seconds):
        """
        Set User defer message duration (seconds) for Quick Scan
        """
        return self.set_fs_user_defer_msg_duration(int_seconds, 'QS')

    qs_user_defer_msg_duration = property(get_qs_user_defer_msg_duration,
                                          set_qs_user_defer_msg_duration)

    #   Scan anytime: User can pause and cancel scans
    def get_qs_user_pause_cancel(self):
        """
        Get User can pause and cancel scans for Quick Scan
        """
        return self.get_fs_user_pause_cancel('QS')

    def set_qs_user_pause_cancel(self, mode):
        """
        Set User can pause and cancel scans for Quick Scan
        """
        return self.set_fs_user_pause_cancel(mode, 'QS')

    qs_user_pause_cancel = property(get_qs_user_pause_cancel, set_qs_user_pause_cancel)

    #   Scan anytime: Do not scan when the system is in presentation mode
    def get_qs_not_in_presentation(self):
        """
        Get Do not scan when the system is in presentation mode for Quick Scan
        """
        return self.get_fs_not_in_presentation('QS')

    def set_qs_not_in_presentation(self, mode):
        """
        Get Do not scan when the system is in presentation mode for Quick Scan
        """
        return self.set_fs_not_in_presentation(mode, 'QS')

    qs_not_in_presentation = property(get_qs_not_in_presentation, set_qs_not_in_presentation)

    #   Do not scan when the system is on battery power
    def get_qs_not_on_battery(self):
        """
        Get Do not scan when the system is on battery power for Quick Scan
        """
        return self.get_fs_not_on_battery('QS')

    def set_qs_not_on_battery(self, mode):
        """
        Get Do not scan when the system is on battery power for Quick Scan
        """
        return self.set_fs_not_on_battery(mode, 'QS')

    qs_not_on_battery = property(get_qs_not_on_battery, set_qs_not_on_battery)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Performance:
    #   Use the scan cache
    def get_qs_use_cache(self):
        """
        Get Use the scan cache for Quick Scan
        """
        return self.get_fs_use_cache('QS')

    def set_qs_use_cache(self, mode):
        """
        Get Use the scan cache for Quick Scan
        """
        return self.set_fs_use_cache(mode, 'QS')

    qs_use_cache = property(get_qs_use_cache, set_qs_use_cache)

    # Performance:
    #    System utilization or Limit maximum CPU usage
    def get_qs_performance_level(self):
        """
        Get Performance level for Quick Scan
        """
        return self.get_fs_performance_level('QS')

    def set_qs_performance_level(self, level):
        """
        Set Performance level for Quick Scan
        """
        return self.set_fs_performance_level(level, 'QS')

    qs_performance_level = property(get_qs_performance_level, set_qs_performance_level)

    #   System utilization (Low, Below normal or Normal)
    def get_qs_perf_system_utilization(self):
        """
        Get System utilization level for Quick Scan
        """
        return self.get_fs_perf_system_utilization('QS')

    def set_qs_perf_system_utilization(self, level):
        """
        Set System utilization level for Quick Scan
        """
        return self.set_fs_perf_system_utilization(level, 'QS')

    qs_perf_system_utilization = property(get_qs_perf_system_utilization,
                                          set_qs_perf_system_utilization)

    #   Limit maximum CPU usage (Available only when Scan anytime is selected) Percentage (25-99)
    def get_qs_perf_max_cpu(self):
        """
        Get Limit maximum CPU usage for Quick Scan
        """
        return self.get_fs_perf_max_cpu('QS')

    def set_qs_perf_max_cpu(self, int_percentage):
        """
        Set Limit maximum CPU usage for Quick Scan
        """
        return self.set_fs_perf_max_cpu(int_percentage, 'QS')

    qs_perf_max_cpu = property(get_qs_perf_max_cpu, set_qs_perf_max_cpu)

    # ------------------------------ On-Demand Policy - Quick Scan ------------------------------
    # Account: Enter user account for scanning networks devices
    #   User name
    def get_qs_user_name(self):
        """
        Get User name for scanning networks devices during Quick Scan
        """
        return self.get_fs_user_name('QS')

    def set_qs_user_name(self, user_name):
        """
        Set User name for scanning networks devices during Quick Scan
        """
        return self.set_fs_user_name(user_name, 'QS')

    qs_user_name = property(get_qs_user_name, set_qs_user_name)

    #   Password
    def get_qs_user_password(self):
        """
        Get Password for scanning network devices during Quick Scan
        """
        return self.get_fs_user_password('QS')

    def set_qs_user_password(self, password):
        """
        Set Password for scanning network devices during Quick Scan
        """
        return self.set_fs_user_password(password, 'QS')

    qs_user_password = property(get_qs_user_password, set_qs_user_password)

    #   Domain
    def get_qs_domain_name(self):
        """
        Get Domain name for scanning networks devices during Quick Scan
        """
        return self.get_fs_domain_name('QS')

    def set_qs_domain_name(self, domain_name):
        """
        Set Domain name for scanning networks devices during Quick Scan
        """
        return self.set_fs_domain_name(domain_name, 'QS')

    qs_domain_name = property(get_qs_domain_name, set_qs_domain_name)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # What to Scan:
    #   Boot sectors
    def get_rs_boot_sectors(self):
        """
        Get Scan boot sectors for Right-click Scan
        """
        return self.get_fs_boot_sectors('RS')

    def set_rs_boot_sectors(self, mode):
        """
        Set Scan boot sectors for Right-click Scan
        """
        return self.set_fs_boot_sectors(mode, 'RS')

    rs_boot_sectors = property(get_rs_boot_sectors, set_rs_boot_sectors)

    #   Files that have been migrated to storage
    def get_rs_files_to_storage(self):
        """
        Get Files migrated to storage for Right-click Scan
        """
        return self.get_fs_files_to_storage('RS')

    def set_rs_files_to_storage(self, mode):
        """
        Set Files migrated to storage for Right-click Scan
        """
        return self.set_fs_files_to_storage(mode, 'RS')

    rs_files_to_storage = property(get_rs_files_to_storage, set_rs_files_to_storage)

    #   Compressed MIME-encoded files
    def get_rs_mime(self):
        """
        Get Compressed MIME-encoded files for Right-click Scan
        """
        return self.get_fs_mime('RS')

    def set_rs_mime(self, mode):
        """
        Set Compressed MIME-encoded files for Right-click Scan
        """
        return self.set_fs_mime(mode, 'RS')

    rs_mime = property(get_rs_mime, set_rs_mime)

    #   Compressed archives files
    def get_rs_archives(self):
        """
        Get Compressed archive files for Right-click Scan
        """
        return self.get_fs_archives('RS')

    def set_rs_archives(self, mode):
        """
        Set Compressed archive files for Right-click Scan
        """
        return self.set_fs_archives(mode, 'RS')

    rs_archives = property(get_rs_archives, set_rs_archives)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # Additional Scan Options:
    #   Detect unwanted programs
    def get_rs_pup(self):
        """
        Get Detect unwanted programs for Right-click Scan
        """
        return self.get_fs_pup('RS')

    def set_rs_pup(self, mode):
        """
        Set Detect unwanted programs for Right-click Scan
        """
        return self.set_fs_pup(mode, 'RS')

    rs_pup = property(get_rs_pup, set_rs_pup)

    #   Detect unknown program threats
    def get_rs_unknown_threats(self):
        """
        Get Detect unknown program threats for Right-click Scan
        """
        return self.get_fs_unknown_threats('RS')

    def set_rs_unknown_threats(self, mode):
        """
        Set Detect unknown program threats for Right-click Scan
        """
        return self.set_fs_unknown_threats(mode, 'RS')

    rs_unknown_threats = property(get_rs_unknown_threats, set_rs_unknown_threats)

    #   Detect unknown macro threats
    def get_rs_unknown_macro(self):
        """
        Get Detect unknown macro threats for Right-click Scan
        """
        return self.get_fs_unknown_macro('RS')

    def set_rs_unknown_macro(self, mode):
        """
        Set Detect unknown macro threats for Right-click Scan
        """
        return self.set_fs_unknown_macro(mode, 'RS')

    rs_unknown_macro = property(get_rs_unknown_macro, set_rs_unknown_macro)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # Scan Locations:
    #   Scan subfolders
    def get_rs_subfolders(self):
        """
        Get Scan subfolders for Right-click Scan
        """
        return self.get_fs_subfolders('RS')

    def set_rs_subfolders(self, mode):
        """
        Set Scan subfolders for Right-click Scan
        """
        return self.set_fs_subfolders(mode, 'RS')

    rs_subfolders = property(get_rs_subfolders, set_rs_subfolders)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # File Types to Scan:
    #   All files
    #   Default and speciied file types
    #   Specified file types only
    def get_rs_file_types(self):
        """
        Get File types to Scan for Right-click Scan
        """
        return self.get_fs_file_types('RS')

    def set_rs_file_types(self, level, extensions=''):
        """
        Set File types to scan for Right-click Scan
        """
        return self.set_fs_file_types(level, extensions, 'RS')

    rs_file_types = property(get_rs_file_types, set_rs_file_types)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # McAfee GTI:
    #   Enable McAfee GTI / Sensitivity level
    #   0 = OFF         Gti().DISABLED
    #   1 = Very Low    Gti().VERY_LOW
    #   2 = Low         Gti().LOW
    #   3 = Medium      Gti().MEDIUM
    #   4 = High        Gti().HIGH
    #   5 = Very High   Gti().VERY_HIGH
    def get_rs_gti_level(self):
        """
        Get the GTI level (Use Gti class from constants) for Right-click Scan
        """
        return self.get_fs_gti_level('RS')

    def set_rs_gti_level(self, level):
        """
        Set the GTI level (Use Gti class from constants) for Right-click Scan
        """
        return self.set_fs_gti_level(level, 'RS')

    rs_gti_level = property(get_rs_gti_level, set_rs_gti_level)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # Exclusions:
    #   Exclusions
    def get_rs_exclusion_list(self):
        """
        Get exclusions list for Right-click Scan
        Return a list that can be used as ProcessList object.
        """
        return self.get_fs_exclusion_list('RS')

    def set_rs_exclusion_list(self, table):
        """
        Set exclusions list for Right-click Scan
        Use a list or a ProcessList object as input
        """
        return self.set_fs_exclusion_list(table, 'RS')

    rs_exclusion_list = property(get_rs_exclusion_list, set_rs_exclusion_list)

    #   Overwrite exclusions configured on the client
    def get_rs_overwrite_exclusions(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client
        """
        return self.get_fs_overwrite_exclusions('RS')

    def set_rs_overwrite_exclusions(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client
        """
        return self.set_fs_overwrite_exclusions(mode, 'RS')

    rs_overwrite_exclusions = property(get_rs_overwrite_exclusions, set_rs_overwrite_exclusions)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # Actions:
    #   Threat detection first response
    def get_rs_threat_first_response(self):
        """
        Get Action - Threat detection first response for Right-click Scan
        Return the value of the current level
        """
        return self.get_fs_threat_first_response('RS')

    def set_rs_threat_first_response(self, action):
        """
        Set Action - Threat detection first response for Right-click Scan
        """
        return self.set_fs_threat_first_response(action, 'RS')

    rs_threat_first_response = property(get_rs_threat_first_response,
                                        set_rs_threat_first_response)

    #   If first response fails
    def get_rs_threat_second_response(self):
        """
        Get Action - If first response fails for Right-click Scan
        Secondary action must greater than the first one
        """
        return self.get_fs_threat_second_response('RS')

    def set_rs_threat_second_response(self, action):
        """
        Set Action - If first response fails for Right-click Scan
        Secondary action must greater than the first one
        """
        return self.set_fs_threat_second_response(action, 'RS')

    rs_threat_second_response = property(get_rs_threat_second_response,
                                         set_rs_threat_second_response)

    #   Unwanted program first response
    def get_rs_pup_first_response(self):
        """
        Get Action - Unwanted program first response:
        """
        return self.get_fs_pup_first_response('RS')

    def set_rs_pup_first_response(self, action):
        """
        Set Action - Unwanted program first response:
        """
        return self.set_fs_pup_first_response(action, 'RS')

    rs_pup_first_response = property(get_rs_pup_first_response,
                                     set_rs_pup_first_response)

    #   If first response fails
    def get_rs_pup_second_response(self):
        """
        Get Action - If first response fails:
        """
        return self.get_fs_pup_second_response('RS')

    def set_rs_pup_second_response(self, action):
        """
        Set Action - If first response fails:
        """
        return self.set_fs_pup_second_response(action, 'RS')

    rs_pup_second_response = property(get_rs_pup_second_response,
                                      set_rs_pup_second_response)

    # ------------------------------ On-Demand Policy - Right-click Scan ------------------------------
    # Performance:
    #   Use the scan cache
    def get_rs_use_cache(self):
        """
        Get Use the scan cache for Right-click Scan
        """
        return self.get_fs_use_cache('RS')

    def set_rs_use_cache(self, mode):
        """
        Get Use the scan cache for Right-click Scan
        """
        return self.set_fs_use_cache(mode, 'RS')

    rs_use_cache = property(get_rs_use_cache, set_rs_use_cache)

    # Performance:
    #   System utilization (Low, Below normal or Normal)
    def get_rs_perf_system_utilization(self):
        """
        Get System utilization level for Right-click Scan
        """
        return self.get_fs_perf_system_utilization('RS')

    def set_rs_perf_system_utilization(self, level):
        """
        Set System utilization level for Right-click Scan
        """
        return self.set_fs_perf_system_utilization(level, 'RS')

    rs_perf_system_utilization = property(get_rs_perf_system_utilization,
                                          set_rs_perf_system_utilization)

class ODSLocationList():
    """
    The ODSLocationList class can be used to edit the list of locations.

    Possible locations are defined like that:
        'SpecialScanForRootkits':   'Memory for rootkits'
        'SpecialMemory':            'Running processes'
        'SpecialCritical':          'Registered files'
        'My Computer':              'My computer'
        'LocalDrives':              'All local drives'
        'All fixed disks':          'All fixed drives'
        'All removable media':      'All removable drives'
        'All Network drives':       'All mapped drives'
        'HomeDir':                  'Home folder'
        'ProfileDir':               'User profile folder'
        'WinDir':                   'Windows folder'
        'ProgramFilesDir':          'Program files folder'
        'TempDir':                  'Temp folder'
        'SpecialRecycleName':       'Recycle bin'
        'SpecialRegistry':          'Registry'

    Note for 'File or folder' simply use the full path directly.
    """

    def __init__(self, location_list = list()):
        self.loc_list = location_list

    def __repr__(self):
        return '<ODSLocationList which contains {} location(s)>'.format(len(self.loc_list))

    def __str__(self):
        names = {'SpecialScanForRootkits': 'Memory for rootkits',
                 'SpecialMemory': 'Running processes',
                 'SpecialCritical': 'Registered files',
                 'My Computer': 'My computer',
                 'LocalDrives': 'All local drives',
                 'All fixed disks': 'All fixed drives',
                 'All removable media': 'All removable drives',
                 'All Network drives': 'All mapped drives',
                 'HomeDir': 'Home folder',
                 'ProfileDir': 'User profile folder',
                 'WinDir': 'Windows folder',
                 'ProgramFilesDir': 'Program files folder',
                 'TempDir': 'Temp folder',
                 'SpecialRecycleName': 'Recycle bin',
                 'SpecialRegistry': 'Registry'}
        builtin = [row for row in names.keys()]
        txt = '| {0:40}|\n'.format('Scan Locations')
        txt += '|:----------------------------------------|'
        for row in self.loc_list:
            if row in builtin:
                row = names[row]
            else:
                row = 'File or folder = ' + row
            txt += '\n| {0:40}|'.format(row)
        return txt

    def __add(self, loc):
        """
        Add a location in the location list.
        :loc: Any possible location.
        """
        success = False
        if not self.contains(loc):
            self.loc_list.append(loc)
            success = True
        return success

    def add_default(self, location):
        """
        Add one of builtin possible locations.
        Possible location value are:
        'SpecialScanForRootkits':   'Memory for rootkits'
        'SpecialMemory':            'Running processes'
        'SpecialCritical':          'Registered files'
        'My Computer':              'My computer'
        'LocalDrives':              'All local drives'
        'All fixed disks':          'All fixed drives'
        'All removable media':      'All removable drives'
        'All Network drives':       'All mapped drives'
        'HomeDir':                  'Home folder'
        'ProfileDir':               'User profile folder'
        'WinDir':                   'Windows folder'
        'ProgramFilesDir':          'Program files folder'
        'TempDir':                  'Temp folder'
        'SpecialRecycleName':       'Recycle bin'
        'SpecialRegistry':          'Registry'
        """
        success = False
        if location in ['SpecialScanForRootkits', 'SpecialMemory', 'SpecialCritical',
                           'My Computer', 'LocalDrives', 'All fixed disks', 'All removable media',
                           'All Network drives', 'HomeDir', 'ProfileDir', 'WinDir',
                           'ProgramFilesDir', 'TempDir', 'SpecialRecycleName', 'SpecialRegistry']:
            success = self.__add(location)
        return success

    def add_file_or_folder(self, full_path):
        """
        Add a file or folder as a location
        :full_path: The full path for the file or the folder.
        """
        return self.__add(full_path)

    def remove(self, location):
        """
        Remove a location
        :location: The location to be removed.
        """
        self.loc_list.remove(location)
        return True

    def remove_all(self):
        """
        Remove all existing locations
        """
        self.loc_list.clear()
        return True

    def contains(self, location):
        """
        Return True if the location list contains the location.
        :location: The location to look for.
        """
        search = [row for row in self.loc_list if row == location]
        return len(search) >= 1

class ODSExclusionList(ExclusionList):
    pass