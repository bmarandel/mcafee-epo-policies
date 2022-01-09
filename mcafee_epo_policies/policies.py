# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines two Class object: Policies and Policy.
Those classes will be used as the base Class object to create other modules for each
product policy managed by ePolicy Orchestrator.
"""

import uuid
import copy
import xml.etree.ElementTree as et

class XmlObject():
    """
    XmlObject is a common class object for Policies and Policy.
    """

    def __init__(self):
        self.root = None

    def is_empty(self):
        """
        Returns True if the object is empty, other else False.

        :return: True or False.
        """
        return self.root is None

    def get_xml_content(self):
        """
        Returns the current XML content, UTF-8 encoded (binary).
        """
        return et.tostring(self.root, encoding='utf8', method='xml')

    def set_xml_content(self, xml_data):
        """
        Set the data of the XML object.
        """
        self.root = et.fromstring(xml_data)

    def get_xml_content_str(self):
        """
        Returns the current XML content, UTF-8 decoded (string).
        """
        return self.get_xml_content().decode()

    def load_from_file(self, file_path):
        """
        Load a Policy from a previously export policy file from an ePO server.
        """
        tree = et.parse(file_path)
        self.root = tree.getroot()

    def save_to_file(self, file_path):
        """
        Save the current Policy in an XML file. This file can be imported into an ePO server.
        """
        success = False
        if self.root is not None:
            xml_file = open(file_path, 'bw')
            xml_file.write(self.get_xml_content())
            xml_file.close()
            success = True
        return success

    def get_epo_version(self):
        """
        Returns the ePO server version from XML content.
        """
        str_version = ''
        if self.root is not None:
            policy_ver = self.root.find('EPOPolicyVerInfo')
            epo_version = policy_ver.attrib
            str_version = '{vermjr}.{vermin}.{verrel}.{verbld}'.format(**epo_version)
        return str_version

    def get_epo_server(self):
        """
        Returns the ePO Server name which this Policy come from.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['serverid'] if policy_obj is not None else ''

    def get_product(self):
        """
        Returns the product name of which this Policy should apply.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['featureid'] if policy_obj is not None else ''

class Policies(XmlObject):
    """
    Policies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(Policies, self).__init__()
        if xml_policies is not None:
            self.set_xml_content(xml_policies)

    def contain(self, type_id, name):
        """
        Returns True if the current Policies contains a policy (name) for a specific
        type (type_id).

        :param: type_id: The type of the policy.
        :param: name: The name of the policy.
        :return: True or False.
        """
        policy_obj = self.root.find('./EPOPolicyObject[@name="{}"]'.format(name) +
                                    '[@typeid="{}"]'.format(type_id))
        return policy_obj is not None

    def list_name(self):
        """
        Returns a list of policy name found in Policies.
        """
        distinct_names = list(set(policy_obj.attrib['name']
                                  for policy_obj in self.root.findall('EPOPolicyObject')))
        sorted_names = sorted(distinct_names)
        return sorted_names

    def list_type(self):
        """
        Returns a list of policy type found in Policies.
        """
        distinct_types = list(set(policy_obj.attrib['typeid']
                                  for policy_obj in self.root.findall('EPOPolicyObject')))
        sorted_types = sorted(distinct_types)
        return sorted_types

    def list(self):
        """
        Returns a table containing the list of policy name for each policy type found in Policies.
        """
        full_list = [{'typeid': policy_obj.attrib['typeid'], 'name': policy_obj.attrib['name']}
                     for policy_obj in self.root.findall('EPOPolicyObject')]
        sorted_list = sorted(full_list, key=lambda x: (x['typeid'], x['name']))
        return sorted_list

    def get_policy(self, type_id, name):
        """
        Returns a Policy content of a policy (name) for a specific type (type_id).
        """
        if self.contain(type_id, name):
            policy = copy.deepcopy(self.root)
            for policy_obj in policy.findall('EPOPolicyObject'):
                if (policy_obj.attrib['typeid'] == type_id) and (policy_obj.attrib['name'] == name):
                    policy_ref = policy_obj.find('PolicySettings').text
                else:
                    policy.remove(policy_obj)
            for policy_obj in policy.findall('EPOPolicySettings'):
                if policy_obj.attrib['name'] != policy_ref:
                    policy.remove(policy_obj)
        else:
            policy = None
        return policy

    def new_policy(self, type_id, name, template='My Default'):
        """
        Returns a new Policy with a policy name (name) for a specific type (type_id).
        herited from a template (default="My Default").
        """
        policy = self.get_policy(type_id, template)
        if policy is not None:
            policy_ref = '{}::Settings ({})'.format(name, str(uuid.uuid4()).upper())
            policy_obj = policy.find('EPOPolicySettings')
            policy_obj.set('name', policy_ref)
            policy_obj = policy.find('EPOPolicyObject')
            policy_obj.set('name', name)
            policy_obj.find('PolicySettings').text = policy_ref
        return policy


class Policy(XmlObject):
    """
    Policy is a class object containing one Policy from Policies.
    """

    def __init__(self, policy_from_policies):
        super(Policy, self).__init__()
        self.root = policy_from_policies

    def get_name(self):
        """
        Returns the name of the Policy.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['name'] if policy_obj is not None else ''

    def get_type(self):
        """
        Returns the type of the Policy.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['typeid'] if policy_obj is not None else ''

    def get_setting_value(self, section, setting):
        """
        Returns the current value of a Setting from a specific Section.

        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :return: The value of the setting or None if the setting doesn't exist.
        """
        setting_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_setting_value(self, section, setting, value, force=False):
        """
        Set the value of an existing Setting for a specific Section.

        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :param: force: If True the setting is created even if it doesn't exist.
        :return: True or False.
        """
        success = False
        setting_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        if setting_obj is not None:
            setting_obj.set('value', value)
            success = True
        elif force:
            section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
            setting_obj = et.SubElement(section_obj, 'Setting', {"name":setting, "value":value})
            success = True
        return success
