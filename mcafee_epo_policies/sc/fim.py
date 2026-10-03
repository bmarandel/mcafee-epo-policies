# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class for the Solidcore "Integrity Monitor" policies
(SCOR_FIM): SCFIMPolicyRules.
"""

import uuid
from .scpolicies import SCPolicy
from .rules import SCRules

class SCFIMRules(SCRules):
    """
    SCFIMRules gives the methods of the Integrity Monitoring Rules tabs of the
    ePO console, for Integrity Monitoring Rules policies (SCFIMPolicyRules) and
    Integrity Monitor Rule Groups (SCFIMRuleGroup).
    """

    # File encoding values (Content Change Tracking).
    ENCODINGS = ('AutoDetect', 'ASCII', 'UTF8', 'UTF-16')

    def __get_patterns(self, rule_type):
        return [{'pattern': r.get('pattern'), 'action': r.get('action')}
                for r in self.get_rules(rule_type)]

    def __add_pattern(self, rule_type, pattern, include):
        if self.get_rules(rule_type, {'pattern': pattern}):
            return False
        return self.add_rule({'type': rule_type, 'pattern': pattern,
                              'action': 'Include' if include else 'Exclude'})

    def __remove_pattern(self, rule_type, pattern):
        return self.remove_rules(rule_type, {'pattern': pattern}) > 0

    def __check_encoding(self, encoding):
        if encoding not in self.ENCODINGS:
            raise ValueError('File encoding must be one of {}.'.format(', '.join(self.ENCODINGS)))

    # ------------------------------ FILE TAB ------------------------------
    #   Columns: Filter, Path, Change Tracking Settings, Include Patterns,
    #   Exclude Patterns.
    #   A file (or a directory without content tracking) is a 'mon-file' rule,
    #   with file-diff/file-encoding when Enable Content Change Tracking is
    #   checked. A directory with content change tracking (Is Directory) is a
    #   'file-diff-dir' rule, with Recurse Directory and Include/Exclude Patterns.
    def get_file_list(self):
        """
        Get the list of monitored files and directories, as dicts {'pattern',
        'action', 'change_tracking' (bool), 'encoding', 'is_directory' (bool),
        'recurse' (bool), 'include_patterns' (list), 'exclude_patterns' (list)}.
        """
        files = []
        for rule in self.get_rules('mon-file'):
            files.append({'pattern': rule.get('pattern'), 'action': rule.get('action'),
                          'change_tracking': rule.get('file-diff') == 'true',
                          'encoding': rule.get('file-encoding'), 'is_directory': False,
                          'recurse': False, 'include_patterns': [], 'exclude_patterns': []})
        for rule in self.get_rules('file-diff-dir'):
            patterns = {}
            for kind in ('include', 'exclude'):
                count = int(rule.get('{}-pattern-count'.format(kind), '0'))
                patterns[kind] = [rule.get('{}-pattern_{}'.format(kind, i))
                                  for i in range(1, count + 1)]
            files.append({'pattern': rule.get('pattern'), 'action': 'Include',
                          'change_tracking': True, 'encoding': rule.get('file-encoding'),
                          'is_directory': True, 'recurse': rule.get('recurse-dir') == 'true',
                          'include_patterns': patterns['include'],
                          'exclude_patterns': patterns['exclude']})
        return files

    def add_file(self, path, include=True, change_tracking=False, encoding='AutoDetect'):
        """
        Add a monitored file or directory (Include), or exclude it (Exclude).

        :param: change_tracking: Enable Content Change Tracking (files only).
        :param: encoding: File encoding (see ENCODINGS) when change_tracking is True.
        :return: True, or False if the path is already in the list.
        """
        if self.get_rules('mon-file', {'pattern': path}):
            return False
        rule = {'type': 'mon-file', 'pattern': path, 'action': 'Include' if include else 'Exclude'}
        if change_tracking:
            self.__check_encoding(encoding)
            rule.update({'file-diff': 'true', 'file-encoding': encoding})
        return self.add_rule(rule)

    def add_directory_change_tracking(self, path, recurse=True, include_patterns=('*',),
                                      exclude_patterns=(), encoding='AutoDetect'):
        """
        Add a directory with Content Change Tracking (Is Directory checked).

        :param: recurse: Recurse Directory checkbox.
        :param: include_patterns: Include Patterns (e.g. ['*.cfg']).
        :param: exclude_patterns: Exclude Patterns (e.g. ['*.tmp']).
        :return: True, or False if the directory is already in the list.
        """
        if self.get_rules('file-diff-dir', {'pattern': path}):
            return False
        self.__check_encoding(encoding)
        rule = {'type': 'file-diff-dir', 'pattern': path, 'file-encoding': encoding,
                'recurse-dir': 'true' if recurse else 'false',
                'include-pattern-count': str(len(include_patterns)),
                'exclude-pattern-count': str(len(exclude_patterns))}
        for kind, patterns in (('include', include_patterns), ('exclude', exclude_patterns)):
            for index, pattern in enumerate(patterns, 1):
                rule['{}-pattern_{}'.format(kind, index)] = pattern
        return self.add_rule(rule)

    def remove_file(self, path):
        """
        Remove a file or directory from the File list.
        """
        count = self.remove_rules('mon-file', {'pattern': path})
        count += self.remove_rules('file-diff-dir', {'pattern': path})
        return count > 0

    # ------------------------------ REGISTRY TAB ------------------------------
    #   Columns: Filter, Registry (a registry key). Windows only.
    def get_registry_list(self):
        """
        Get the list of monitored registry keys ('mon-reg' rules).
        """
        return self.__get_patterns('mon-reg')

    def add_registry(self, key, include=True):
        """
        Add a monitored registry key (Include), or exclude it (Exclude).
        """
        return self.__add_pattern('mon-reg', key, include)

    def remove_registry(self, key):
        """
        Remove a registry key from the Registry list.
        """
        return self.__remove_pattern('mon-reg', key)

    # ------------------------------ EXTENSION TAB ------------------------------
    #   Columns: Filter, Extension (e.g. 'log', without the dot).
    def get_extension_list(self):
        """
        Get the list of file extensions ('mon-extn' rules).
        """
        return self.__get_patterns('mon-extn')

    def add_extension(self, extension, include=False):
        """
        Add a file extension, excluded by default (Exclude) or included (Include).
        """
        return self.__add_pattern('mon-extn', extension, include)

    def remove_extension(self, extension):
        """
        Remove a file extension from the Extension list.
        """
        return self.__remove_pattern('mon-extn', extension)

    # ------------------------------ PROGRAM TAB ------------------------------
    #   Columns: Filter, Program (the changes made by a program).
    def get_program_list(self):
        """
        Get the list of programs ('mon-proc' rules).
        """
        return self.__get_patterns('mon-proc')

    def add_program(self, program, include=False):
        """
        Add a program, excluded by default (Exclude) or included (Include).
        """
        return self.__add_pattern('mon-proc', program, include)

    def remove_program(self, program):
        """
        Remove a program from the Program list.
        """
        return self.__remove_pattern('mon-proc', program)

    # ------------------------------ USER TAB ------------------------------
    #   Columns: Filter, User (the changes made by a user). Windows only.
    def get_user_list(self):
        """
        Get the list of users ('mon-user' rules).
        """
        return self.__get_patterns('mon-user')

    def add_user(self, user, include=False):
        """
        Add a user, excluded by default (Exclude) or included (Include).
        """
        return self.__add_pattern('mon-user', user, include)

    def remove_user(self, user):
        """
        Remove a user from the User list.
        """
        return self.__remove_pattern('mon-user', user)

    # ------------------------------ FILTERS TAB ------------------------------
    #   Advanced filters excluding events: lists of conditions (AND), as dicts
    #   {'condition', 'match', 'pattern'} (see SCPolicy.get_conditions()).
    #   Conditions: File, Event, Process (Program), Reg (Registry), User; match:
    #   equals, begins, ends, contains, doesnt_contain (always equals for Event).
    #   Event names are in upper case, e.g. 'FILE_MODIFIED' (console "File
    #   Modified"). Stored as 'mon-advanced' rules (older Trellix rule groups
    #   have no rule-uuid).
    def get_filters(self):
        """
        Get the list of filters, as dicts {'uuid', 'conditions'}.
        """
        return [{'uuid': r.get('rule-uuid'), 'conditions': self.get_conditions(r)}
                for r in self.get_rules('mon-advanced')]

    def add_filter(self, conditions):
        """
        Add a filter.

        :param: conditions: A list of (condition, match, pattern) tuples or dicts,
                            e.g. [('Event', 'equals', 'FILE_MODIFIED'),
                                  ('Process', 'equals', 'backup.exe')].
        :return: The rule-uuid of the new filter.
        """
        rule_uuid = str(uuid.uuid4())
        rule = {'type': 'mon-advanced', 'action': 'exclude', 'rule-uuid': rule_uuid}
        rule.update(self.make_conditions(conditions))
        self.add_rule(rule)
        return rule_uuid

    def remove_filter(self, rule_uuid):
        """
        Remove a filter by its rule-uuid.
        """
        return self.remove_rules('mon-advanced', {'rule-uuid': rule_uuid}) > 0


class SCFIMPolicyRules(SCFIMRules, SCPolicy):
    """
    The SCFIMPolicyRules class can be used to edit the Solidcore policies:
    Integrity Monitor > Integrity Monitoring Rules (Windows) and (Unix).

    Note: ePO stores these policies under the internal types "Mon Rules (Windows)"
    and "Mon Rules (Unix)". Only the policy's own rules ("My Rules") are edited;
    see SCPolicy for the shared Rule Groups (e.g. the "Base Filters" groups).
    The File, Registry, Extension, Program and User tabs are lists of
    {'pattern', 'action'} rules, where action is 'Include' or 'Exclude' (the
    Filter column; older Trellix rule groups store it in lower case). The
    longest pathname takes precedence.
    """

    TYPE_IDS = ('Mon Rules (Windows)', 'Mon Rules (Unix)')
