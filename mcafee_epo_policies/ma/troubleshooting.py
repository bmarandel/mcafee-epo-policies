# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class McAfeeAgentPolicyTroubleshooting.
"""

from ..policies import Policy

class McAfeeAgentPolicyTroubleshooting(Policy):
    """
    The McAfeeAgentPolicyTroubleshooting class can be used to edit the McAfee Agent
    policy: Troubleshooting.

    Note: ServerId (a per-installation ePO server GUID) is intentionally not
    exposed here - it is internal to the ePO server and not a user setting.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(McAfeeAgentPolicyTroubleshooting, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'Troubleshooting':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "Troubleshooting".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<McAfeeAgentPolicyTroubleshooting for policy {} from server {}.>'.format(name, epo)

    # ------------------------------ GENERAL TAB ------------------------------
    # Language Options:
    #   Select language used by agent
    def get_enable_agent_language_selection(self):
        """
        Get state of Select language used by agent
        """
        value = self.get_setting_value('LanguageOptions', 'bEnableAgentLangSelection')
        return value if value is not None else self.get_setting_value(
            'General', 'bEnableAgentLangSelection')

    def set_enable_agent_language_selection(self, mode):
        """
        Set state of Select language used by agent
        """
        self.set_setting_value('LanguageOptions', 'bEnableAgentLangSelection', mode)
        return self.set_setting_value('General', 'bEnableAgentLangSelection', mode)

    enable_agent_language_selection = property(get_enable_agent_language_selection,
                                               set_enable_agent_language_selection)

    #   Language dropdown, available once "Select language used by agent" is checked.
    #   Value is a Windows LCID hex code (use the Language class from constants,
    #   e.g. Language.FRENCH, instead of remembering the raw code).
    def get_agent_language(self):
        """
        Get the selected agent language (Use Language class from constants)
        """
        value = self.get_setting_value('LanguageOptions', 'AgentLanguage')
        return value if value is not None else self.get_setting_value('General', 'AgentLanguage')

    def set_agent_language(self, language_code):
        """
        Set the selected agent language (Use Language class from constants)
        """
        self.set_setting_value('LanguageOptions', 'AgentLanguage', language_code)
        return self.set_setting_value('General', 'AgentLanguage', language_code)

    agent_language = property(get_agent_language, set_agent_language)

    # ------------------------------ GENERAL TAB ------------------------------
    #   Console label not confirmed - kept for completeness.
    def get_health_check(self):
        """
        Get state of a General tab option (console label not confirmed)
        """
        return self.get_setting_value('General', 'IsHealthcheckEnabled')

    def set_health_check(self, mode):
        """
        Set state of a General tab option (console label not confirmed)
        """
        return self.set_setting_value('General', 'IsHealthcheckEnabled', mode)

    health_check = property(get_health_check, set_health_check)
