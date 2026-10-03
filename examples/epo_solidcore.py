# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
epo_solidcore.py

Helper shared by the Solidcore examples that work directly against an ePO
server: a thin layer over the "mcafee-epo" API client (pip install mcafee-epo)
to export and import Solidcore policies and Rule Groups.

Connection settings are read from the command line (--url, --user), then from
the EPO_URL, EPO_USER and EPO_PASSWORD environment variables. The password is
asked interactively if it isn't set: it is never passed on the command line.
"""

import argparse
import getpass
import os
import sys

from mcafee_epo_policies import SCPolicies, SCRuleGroups

try:
    import mcafee_epo
    import requests
except ImportError:
    sys.exit('These examples need the "mcafee-epo" package: pip install mcafee-epo')

# Solidcore Rule Group types, as expected by the scor.rulegroup.* commands.
API_GROUP_TYPES = {SCRuleGroups.APPLICATION_CONTROL: 'APPLICATION_CONTROL',
                   SCRuleGroups.CHANGE_CONTROL: 'CHANGE_CONTROL',
                   SCRuleGroups.INTEGRITY_MONITOR: 'INTEGRITY_MONITOR'}


def add_connection_arguments(parser):
    """
    Adds the ePO connection options to an argparse parser.
    """
    parser.add_argument('--url', default=os.environ.get('EPO_URL'),
                        help='ePO server URL, e.g. https://epo.example.com:8443 (or EPO_URL)')
    parser.add_argument('--user', default=os.environ.get('EPO_USER'),
                        help='ePO user name (or EPO_USER)')
    parser.add_argument('--insecure', action='store_true',
                        help="don't check the ePO server certificate (lab servers only)")
    parser.add_argument('--dry-run', action='store_true',
                        help="write the XML files but don't import anything into ePO")


class SolidcoreEPO():
    """
    Exports and imports Solidcore policies and Rule Groups with the ePO API.
    """

    def __init__(self, url, user, password, verify=True):
        session = requests.Session()
        session.verify = verify
        if not verify:
            requests.packages.urllib3.disable_warnings()
        self.client = mcafee_epo.Client(url, user, password, session=session)

    @classmethod
    def from_arguments(cls, args):
        """
        Connects with the options added by add_connection_arguments().
        """
        if not args.url or not args.user:
            sys.exit('The ePO server URL and user are required (--url/--user or EPO_URL/EPO_USER).')
        password = os.environ.get('EPO_PASSWORD') or getpass.getpass(
            'ePO password for {}: '.format(args.user))
        return cls(args.url, args.user, password, verify=not args.insecure)

    def __text(self, command, *args, **kwargs):
        # The scor.* commands ignore ":output=json": ask for plain text, and look
        # for their own error format ("success: false") in the answer.
        text = self.client(command, *args, params={':output': 'terse'}, **kwargs)
        if 'success: false' in text:
            raise RuntimeError('{} failed: {}'.format(command, text.strip()))
        return text

    # ------------------------------ Policies ------------------------------
    def export_policies(self):
        """
        Returns all the Solidcore policies (SCPolicies).
        """
        return SCPolicies(self.client('policy.export', productId='SOLIDCORE_META').encode('utf-8'))

    def import_policies(self, policy_xml, file_name, force=False):
        """
        Imports a policy XML (bytes, e.g. Policy.get_xml_content()) into ePO.

        :param: force: Replace the existing policies with the same name.
        """
        files = {'file': (os.path.basename(file_name), policy_xml, 'text/xml')}
        return self.client('policy.importPolicy', force=str(force).lower(), files=files)

    # ------------------------------ Rule Groups ------------------------------
    def rule_group_exists(self, platform, group_type, name):
        """
        Returns True if a Rule Group exists in ePO.
        """
        names = self.__text('scor.rulegroup.find', platform, API_GROUP_TYPES[group_type])
        return name in [line.strip() for line in names.splitlines()]

    def export_rule_group(self, platform, group_type, name):
        """
        Returns a Rule Group of ePO (SCAWLRuleGroup, SCCCRuleGroup or SCFIMRuleGroup),
        or None if it doesn't exist.
        """
        if not self.rule_group_exists(platform, group_type, name):
            return None
        text = self.__text('scor.rulegroup.export', platform, API_GROUP_TYPES[group_type],
                           ruleGroupName=name)
        return SCRuleGroups(text.strip().encode('utf-8')).get_rule_group(name)

    def import_rule_groups(self, rule_groups, file_name, override=False):
        """
        Imports Rule Groups (SCRuleGroups) into ePO.

        :param: override: Replace the existing Rule Groups with the same name;
                          without it, the import of an existing Rule Group fails.
        """
        files = {'file': (os.path.basename(file_name), rule_groups.get_xml_content(), 'text/xml')}
        text = self.__text('scor.rulegroup.import', override=str(override).lower(), files=files)
        if 'not imported successfully' in text:
            raise RuntimeError('scor.rulegroup.import failed, check the "Import Solidcore Rule '
                               'Groups" server task: {}'.format(text.strip()))
        return text


def parser(description):
    """
    Returns an argparse parser with the ePO connection options.
    """
    result = argparse.ArgumentParser(description=description)
    add_connection_arguments(result)
    return result
