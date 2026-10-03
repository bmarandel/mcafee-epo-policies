# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the Class objects SCRules, SCExclusionRules and SCUpdaterRules.

Solidcore rules are stored the same way in a policy (Sections named
"General_Rule_<n>" of an ePO policy export) and in a Solidcore Rule Group
(<Rule> elements of a "scor.rulegroup.export" file): a list of settings whose
"type" setting gives the kind of rule. SCRules gives a common access to them, as
dicts {setting name: value}, so that the methods editing the tabs of the ePO
console (SCExclusionRules, SCUpdaterRules, and the Application Control, Change
Control and Integrity Monitor classes) work for both policies and rule groups.
"""

import re

class SCRules():
    """
    SCRules is the base class object giving access to Solidcore rules. A subclass
    stores the rules and must implement _iter_rules, _append_rule, _update_rule,
    _remove_rule and is_unix.
    """

    # ------------------------------ Storage (implemented by subclasses) ------------------------------
    def _iter_rules(self, all_groups=False):
        """
        Yields (handle, rule) for each rule, rule being a dict {setting name: value}
        and handle what _update_rule and _remove_rule need to find it.
        """
        raise NotImplementedError

    def _append_rule(self, rule):
        """
        Stores a new rule (dict of strings). Returns True or False.
        """
        raise NotImplementedError

    def _update_rule(self, handle, values):
        """
        Updates (or adds) settings of a stored rule.
        """
        raise NotImplementedError

    def _remove_rule(self, handle):
        """
        Removes a stored rule.
        """
        raise NotImplementedError

    def is_unix(self):
        """
        Returns True for a Unix policy or rule group.
        """
        raise NotImplementedError

    # ------------------------------ Rules ------------------------------
    def __select(self, rule_type=None, match=None, all_groups=False):
        for handle, rule in self._iter_rules(all_groups):
            if rule_type is not None and rule.get('type') != rule_type:
                continue
            if match and any(rule.get(k) != v for k, v in match.items()):
                continue
            yield handle, rule

    def get_rules(self, rule_type=None, match=None, all_groups=False):
        """
        Returns the list of rules (dicts {setting name: value}).

        :param: rule_type: Only returns rules of this type (e.g. 'updater-binary').
        :param: match: Only returns rules whose settings match this dict.
        :param: all_groups: For a policy, if True, the rules of the shared Rule
                            Groups are also returned, otherwise only the
                            policy's own "My Rules".
        :return: A list of dicts.
        """
        return [rule for _, rule in self.__select(rule_type, match, all_groups)]

    def get_rule(self, rule_type, match=None):
        """
        Returns the first rule (dict) matching a type and the settings given in
        match, or None if there is none.
        """
        rules = self.get_rules(rule_type, match)
        return rules[0] if rules else None

    def add_rule(self, rule):
        """
        Adds a rule (dict {setting name: value}, which must contain a 'type' key).
        For a policy, the rule is added to its own "My Rules".

        :return: True or False (no 'type', or the policy has no "My Rules").
        """
        if 'type' not in rule:
            return False
        return self._append_rule({key: str(value) for key, value in rule.items()})

    def update_rules(self, rule_type, match, values):
        """
        Updates (or adds) settings of the rules matching a type and match.

        :param: rule_type: The type of the rules to update.
        :param: match: A dict of settings the rules must match.
        :param: values: A dict {setting name: new value}.
        :return: The number of rules updated.
        """
        count = 0
        for handle, _ in list(self.__select(rule_type, match)):
            self._update_rule(handle, {key: str(value) for key, value in values.items()})
            count += 1
        return count

    def remove_rules(self, rule_type, match=None):
        """
        Removes the rules matching a type and match.

        :return: The number of rules removed.
        """
        count = 0
        for handle, _ in list(self.__select(rule_type, match)):
            self._remove_rule(handle)
            count += 1
        return count

    # ------------------------------ Typed rule helpers ------------------------------
    #   Rule types present at most once (e.g. 'local-cli-lock').
    def _get_rule_value(self, rule_type, key):
        """
        Returns the value of a setting of the (single) rule of a type, or None.
        """
        rule = self.get_rule(rule_type)
        return rule.get(key) if rule is not None else None

    def _set_rule_value(self, rule_type, key, value):
        """
        Sets the value of a setting of the (single) rule of a type. The rule is
        created if it doesn't exist.
        """
        if self.update_rules(rule_type, None, {key: value}) == 0:
            return self.add_rule({'type': rule_type, key: value})
        return True

    # ------------------------------ Value helpers ------------------------------
    @staticmethod
    def _checksum_key(checksum):
        """
        Returns the setting name of a checksum ('cksum' for SHA-1, 'cksum256' for
        SHA-256), or raises ValueError.
        """
        if re.match(r'^[0-9a-fA-F]{40}$', checksum):
            return 'cksum'
        if re.match(r'^[0-9a-fA-F]{64}$', checksum):
            return 'cksum256'
        raise ValueError('Checksum must be a SHA-1 (40) or SHA-256 (64) hexadecimal value.')

    @staticmethod
    def _bool(value):
        """
        Returns 'true' or 'false'.
        """
        return 'true' if value else 'false'

    # ------------------------------ Conditions ------------------------------
    #   Advanced rules (execution-control, mon-advanced, ob-exclusion,
    #   advanced-inv-exclusion) store a list of conditions as
    #   condition-type_<i> / match-type_<i> / pattern_<i>.
    @staticmethod
    def get_conditions(rule):
        """
        Returns the conditions of an advanced rule as a list of dicts
        {'condition': ..., 'match': ..., 'pattern': ...}.
        """
        conditions = []
        index = 0
        while 'condition-type_{}'.format(index) in rule:
            conditions.append({'condition': rule['condition-type_{}'.format(index)],
                               'match': rule.get('match-type_{}'.format(index)),
                               'pattern': rule.get('pattern_{}'.format(index))})
            index += 1
        return conditions

    @staticmethod
    def make_conditions(conditions):
        """
        Converts a list of conditions (dicts {'condition', 'match', 'pattern'} or
        tuples (condition, match, pattern)) into rule settings.
        """
        settings = {}
        for index, condition in enumerate(conditions):
            if isinstance(condition, dict):
                condition = (condition['condition'], condition['match'], condition['pattern'])
            settings['condition-type_{}'.format(index)] = condition[0]
            settings['match-type_{}'.format(index)] = condition[1]
            settings['pattern_{}'.format(index)] = condition[2]
        return settings


class SCExclusionRules(SCRules):
    """
    SCExclusionRules adds the exclusion list methods to the Solidcore policies and
    rule groups which have one, as edited in the "Add exclusion rules" dialog of
    the ePO console: General > Exception Rules, and the Exclusions tab of
    Application Control Rules.

    Each exclusion is one flag set to 'true' on a rule: an 'attr' rule for a
    process/file name, a 'skiplist' rule for a path or a volume. Use the
    SCException constants to select an exclusion.
    """

    # Exclusions stored as 'skiplist' rules (path), the others are 'attr' rules (file).
    SKIPLIST_EXCLUSIONS = ('skipFileOperation', 'skipFileOperation_f', 'skipDenyWrite',
                           'skipSolidification', 'skipVolume')
    UNIX_EXCLUSIONS = ('process_ctx_bypass', 'skipSolidification')
    # All the exclusions of the console (the SCException constants).
    EXCLUSIONS = ('casp_bypass', 'dep_bypass', 'vasr_force_reloc_bypass', 'vasr_reloc_bypass',
                  'vasr_rand_bypass', 'uninstall_bypass', 'process_ctx_bypass',
                  'process_ctx_reg_bypass') + SKIPLIST_EXCLUSIONS

    # Settings written by the ePO console for a new rule, all flags 'false'.
    __WINDOWS_ATTR_FLAGS = ('always_auth', 'always_unauth', 'anti_debugging_bypass',
                            'casp_bypass', 'ccv_bypass', 'dep_bypass', 'dep_bypass_inherit',
                            'full_crawl', 'installer_detection_bypass', 'mangling_bypass',
                            'process_ctx_bypass', 'process_ctx_reg_bypass', 'rebase_dll',
                            'relocate_dll', 'uninstall_bypass', 'vasr_force_reloc_bypass',
                            'vasr_rand_bypass', 'vasr_reloc_bypass')
    __WINDOWS_SKIPLIST_FLAGS = ('skipChangeTracking', 'skipDenyWrite', 'skipFileOperation',
                                'skipFileOperation_f', 'skipRegistry', 'skipSolidification',
                                'skipVolume')
    __UNIX_ATTR_FLAGS = ('always_auth', 'always_unauth', 'process_ctx_bypass')
    __UNIX_SKIPLIST_FLAGS = ('skipSolidification',)

    def __rule_kind(self, exclusion):
        if exclusion in self.SKIPLIST_EXCLUSIONS:
            return 'skiplist', 'path'
        return 'attr', 'file'

    # ------------------------------ Exclusion list ------------------------------
    #   Columns: Exclusion Type, Process Name (process, file, path or volume)
    def get_exclusion_list(self):
        """
        Get the list of exclusions (Exclusion Type, Process Name columns), as dicts
        {'exclusion': <SCException constant>, 'name': <process, file, path or volume>}.
        """
        exclusions = []
        for rule_type, key in (('skiplist', 'path'), ('attr', 'file')):
            for rule in self.get_rules(rule_type):
                for setting, value in sorted(rule.items()):
                    if value == 'true' and setting in self.EXCLUSIONS:
                        exclusions.append({'exclusion': setting, 'name': rule.get(key)})
        return exclusions

    def contains_exclusion(self, exclusion, name):
        """
        Returns True if the policy contains an exclusion (SCException) for a name.
        """
        rule_type, key = self.__rule_kind(exclusion)
        return bool(self.get_rules(rule_type, {key: name, exclusion: 'true'}))

    def add_exclusion(self, exclusion, name):
        """
        Add an exclusion (SCException constant) for a process, file, path or volume.

        :return: True, or False if the exclusion already exists.
        """
        if self.is_unix() and exclusion not in self.UNIX_EXCLUSIONS:
            raise ValueError('Exclusion "{}" is not available on Unix.'.format(exclusion))
        if self.contains_exclusion(exclusion, name):
            return False
        rule_type, key = self.__rule_kind(exclusion)
        if rule_type == 'skiplist':
            flags = self.__UNIX_SKIPLIST_FLAGS if self.is_unix() else self.__WINDOWS_SKIPLIST_FLAGS
        else:
            flags = self.__UNIX_ATTR_FLAGS if self.is_unix() else self.__WINDOWS_ATTR_FLAGS
        rule = {flag: 'false' for flag in flags}
        rule.update({'type': rule_type, key: name, exclusion: 'true'})
        if rule_type == 'attr':
            rule['is_general_attr'] = 'true'
        return self.add_rule(rule)

    def remove_exclusion(self, exclusion, name):
        """
        Remove an exclusion (SCException constant) for a name. The rule is
        removed once none of its exclusions is set anymore.

        :return: True if the exclusion was found.
        """
        rule_type, key = self.__rule_kind(exclusion)
        match = {key: name, exclusion: 'true'}
        if self.update_rules(rule_type, match, {exclusion: 'false'}) == 0:
            return False
        for rule in self.get_rules(rule_type, {key: name}):
            if not any(v == 'true' for k, v in rule.items() if k != 'is_general_attr'):
                self.remove_rules(rule_type, rule)
        return True


class SCUpdaterRules(SCRules):
    """
    SCUpdaterRules adds the "Updater Processes" and "Users" tabs methods to the
    Solidcore policies and rule groups which have them: Application Control
    Rules and Change Control Rules. Updaters and trusted users can modify any protected file.
    """

    # ------------------------------ UPDATER PROCESSES TAB ------------------------------
    #   Columns: Updater Label, Updater Type, File/SHA-1/SHA-256, Condition,
    #   Parent/Library, Disable Inheritance, Suppress Events.
    #   An updater by name is an 'updater-binary' rule, an updater by SHA-1 or
    #   SHA-256 an 'installer' rule shown as an updater (showas='updater').
    def get_updaters(self):
        """
        Get the list of updaters ('updater-binary' rules and 'installer' rules
        shown as updaters).
        """
        return (self.get_rules('updater-binary') +
                self.get_rules('installer', {'showas': 'updater'}))

    def add_updater(self, file_name, label, parent=None, library=None,
                    disable_inheritance=False, suppress_events=False):
        """
        Add an updater by name (Updater By Name).

        :param: file_name: File Name (a file name or a path).
        :param: label: Updater Label.
        :param: parent: Condition Parent - the parent process name, or None.
        :param: library: Condition Library - the library name, or None.
        :param: disable_inheritance: Disable Inheritance checkbox.
        :param: suppress_events: Suppress Events checkbox.
        """
        if parent and library:
            raise ValueError('Condition must be either Parent or Library, not both.')
        rule = {'type': 'updater-binary', 'binary': file_name, 'tag': label,
                'caseSensitive': 'false', 'inherit': self._bool(not disable_inheritance),
                'log': self._bool(not suppress_events)}
        if parent:
            rule['parent'] = parent
        if library:
            rule['library'] = library
        return self.add_rule(rule)

    def add_updater_by_checksum(self, checksum, label):
        """
        Add an updater by checksum (Updater By File SHA-1 or SHA-256).
        """
        key = self._checksum_key(checksum)
        return self.add_rule({'type': 'installer', key: checksum.lower(), 'tag': label,
                              'ruletype': 'checksum', 'showas': 'updater'})

    def remove_updater(self, label):
        """
        Remove the updater(s) with an Updater Label.

        :return: The number of rules removed.
        """
        return (self.remove_rules('updater-binary', {'tag': label}) +
                self.remove_rules('installer', {'tag': label, 'showas': 'updater'}))

    # ------------------------------ USERS TAB ------------------------------
    #   Columns: Type, UserID/Group, Name, User Label, Include Subgroups.
    #   Trusted users ('updater-user' rules) can modify any protected file.
    def get_trusted_users(self):
        """
        Get the list of trusted users ('updater-user' rules).
        """
        return self.get_rules('updater-user')

    def add_trusted_user(self, user, label, display_name=''):
        """
        Add a trusted user (Domain\\User, User Label, Name).
        """
        return self.add_rule({'type': 'updater-user', 'user': user, 'tag': label,
                              'displayName': display_name, 'activeDirectoryId': '',
                              'groupDN': '', 'netbiosName': ''})

    def remove_trusted_user(self, user):
        """
        Remove a trusted user.
        """
        return self.remove_rules('updater-user', {'user': user}) > 0
