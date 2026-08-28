# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class McAfeeAgentPolicyCustomProps.
"""

from ..policies import Policy

class McAfeeAgentPolicyCustomProps(Policy):
    """
    The McAfeeAgentPolicyCustomProps class can be used to edit the McAfee Agent
    policy: Custom Properties.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(McAfeeAgentPolicyCustomProps, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'CustomProps':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "CustomProps".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<McAfeeAgentPolicyCustomProps for policy {} from server {}.>'.format(name, epo)

    # ------------------------------ Custom Properties ------------------------------
    # The Custom Properties table lists Property 1 through Property 8, each with
    # an "allow client to edit" and a "visible to client" style toggle.
    # Exact column wording not independently confirmed against the ePO console.
    def get_custom_properties(self):
        """
        Get the Custom Properties table (Property 1 through Property 8).
        Returns a list of 8 dicts with keys 'AllowClientEditing' and 'Visibility'.
        """
        return self.get_indexed_table('CustomProps', 'NumberOfCustomProps',
                                      ['AllowClientEditing', 'Visibility'], start=1)

    def set_custom_properties(self, table):
        """
        Set the Custom Properties table (Property 1 through Property 8).
        Use a list of dicts with keys 'AllowClientEditing' and 'Visibility'.
        """
        return self.set_indexed_table('CustomProps', 'NumberOfCustomProps',
                                      ['AllowClientEditing', 'Visibility'], table, start=1)

    custom_properties = property(get_custom_properties, set_custom_properties)

    #   Overwrite blank client-side values with the server value
    #   (exact console label not independently confirmed)
    def get_overwrite_blanks(self):
        """
        Get state of Overwrite blank client-side values with the server value
        """
        return self.get_setting_value('CustomProps', 'OverwriteBlanks')

    def set_overwrite_blanks(self, mode):
        """
        Set state of Overwrite blank client-side values with the server value
        """
        return self.set_setting_value('CustomProps', 'OverwriteBlanks', mode)

    overwrite_blanks = property(get_overwrite_blanks, set_overwrite_blanks)
