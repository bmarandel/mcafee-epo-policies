# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines two Class object: Policies and Policy.
Those classes will be used as the base Class object to create other modules for each
product policy managed by ePolicy Orchestrator.
"""

import re
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
        return et.tostring(self.root, encoding='UTF-8', method='xml')

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
            settings = list()
            for policy_obj in policy.findall('EPOPolicyObject'):
                if (policy_obj.attrib['typeid'] == type_id) and (policy_obj.attrib['name'] == name):
                    for policy_ref in policy_obj.findall('PolicySettings'):
                        settings.append(policy_ref.text)
                else:
                    policy.remove(policy_obj)
            for policy_obj in policy.findall('EPOPolicySettings'):
                if policy_obj.attrib['name'] not in settings:
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
            policy_obj = policy.find('EPOPolicyObject')
            policy_obj.set('name', name)
            for policy_set in policy_obj.findall('PolicySettings'):
                policy_old = policy_set.text
                policy_ref = '{}::Settings ({})'.format(name, str(uuid.uuid4()).upper())
                policy_set.text = policy_ref
                policy_set = policy.find('EPOPolicySettings[@name="{}"]'.format(policy_old))
                policy_set.set('name', policy_ref)
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

    def get_policy_setting_value(self, policy_set, section, setting):
        """
        Returns the current value of a Setting from a specific Section for a PolicySetting.

        :param: policy_set: The EPOPolicySetting where to search for the Section.
        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :return: The value of the setting or None if the setting doesn't exist.
        """
        setting_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                     '/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_policy_setting_value(self, policy_set, section, setting, value, force=False):
        """
        Set the value of an existing Setting for a specific Section and PolicySetting

        :param: policy_set: The EPOPolicySetting where to search for the Section.
        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :param: force: If True the setting is created even if it doesn't exist.
        :return: True or False.
        """
        success = False
        setting_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                     '/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        if setting_obj is not None:
            setting_obj.set('value', value)
            success = True
        elif force:
            section_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                         '/Section[@name="{}"]'.format(section))
            setting_obj = et.SubElement(section_obj, 'Setting', {"name":setting, "value":value})
            success = True
        return success

    def get_indexed_list(self, section, count_setting, item_template, start=0):
        """
        Read a repeating flat list of scalar values: a Setting named
        `count_setting` holds the row count, and one Setting per row is named
        `item_template.format(row)`, rows numbered from `start`.

        :param: section: The Section holding the list.
        :param: count_setting: The Setting name holding the row count.
        :param: item_template: A format string with one "{}" for the row number.
        :param: start: The row number of the first row (default 0).
        :return: A list of strings, or None if the section doesn't exist.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return None
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        max_rows = int(count_obj.get('value')) if count_obj is not None else 0
        values = []
        for row in range(start, start + max_rows):
            setting_obj = section_obj.find('Setting[@name="{}"]'.format(item_template.format(row)))
            values.append(setting_obj.get('value'))
        return values

    def set_indexed_list(self, section, count_setting, item_template, values, start=0):
        """
        Write a repeating flat list (see get_indexed_list). Only the count
        setting and the row settings matching `item_template` are touched;
        any other Setting already present in the section is left untouched.
        The count setting is always written, even when `values` is empty.

        :param: section: The Section holding the list.
        :param: count_setting: The Setting name holding the row count.
        :param: item_template: A format string with one "{}" for the row number.
        :param: values: The list of string values to write.
        :param: start: The row number of the first row (default 0).
        :return: True if the section exists, False otherwise.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return False
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        if count_obj is not None:
            section_obj.remove(count_obj)
        # ePO sometimes leaves stale row settings behind beyond the declared
        # count (e.g. after a site is removed via the console), so cleanup is
        # done by name pattern rather than by trusting the old count value -
        # otherwise a newly written row can collide with a leftover one and
        # get shadowed by it on the next read.
        prefix, _, suffix = item_template.partition('{}')
        pattern = re.compile('^{}\\d+{}$'.format(re.escape(prefix), re.escape(suffix)))
        for setting_obj in section_obj.findall('Setting'):
            if pattern.match(setting_obj.get('name')):
                section_obj.remove(setting_obj)
        et.SubElement(section_obj, 'Setting', {"name":count_setting, "value":str(len(values))})
        for offset, value in enumerate(values):
            row = start + offset
            et.SubElement(section_obj, 'Setting',
                          {"name":item_template.format(row), "value":value})
        return True

    def get_indexed_table(self, section, count_setting, keys, start=0):
        """
        Read a repeating table: a Setting named `count_setting` holds the row
        count, and for each name in `keys`, one Setting per row is named
        "{key}_{row}", rows numbered from `start`.

        :param: section: The Section holding the table.
        :param: count_setting: The Setting name holding the row count.
        :param: keys: The list of column names.
        :param: start: The row number of the first row (default 0).
        :return: A list of dicts (one per row, columns = keys), or None if
                 the section doesn't exist.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return None
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        max_rows = int(count_obj.get('value')) if count_obj is not None else 0
        table = []
        for row in range(start, start + max_rows):
            row_value = {}
            for key in keys:
                setting_obj = section_obj.find('Setting[@name="{}_{}"]'.format(key, row))
                row_value[key] = setting_obj.get('value')
            table.append(row_value)
        return table

    def set_indexed_table(self, section, count_setting, keys, table, start=0):
        """
        Write a repeating table (see get_indexed_table). Only the count
        setting and the "{key}_{row}" settings for `keys` are touched. The
        count setting is always written, even when `table` is empty.

        :param: section: The Section holding the table.
        :param: count_setting: The Setting name holding the row count.
        :param: keys: The list of column names.
        :param: table: The list of dicts (one per row, columns = keys) to write.
        :param: start: The row number of the first row (default 0).
        :return: True if the section exists, False otherwise.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return False
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        if count_obj is not None:
            section_obj.remove(count_obj)
        # See set_indexed_list: cleanup by name pattern, not by the old count,
        # since ePO can leave stale row settings behind beyond it.
        patterns = [re.compile('^{}_\\d+$'.format(re.escape(key))) for key in keys]
        for setting_obj in section_obj.findall('Setting'):
            name = setting_obj.get('name')
            if any(pattern.match(name) for pattern in patterns):
                section_obj.remove(setting_obj)
        et.SubElement(section_obj, 'Setting', {"name":count_setting, "value":str(len(table))})
        for offset, row_value in enumerate(table):
            row = start + offset
            for key in keys:
                et.SubElement(section_obj, 'Setting',
                              {"name":'{}_{}'.format(key, row), "value":row_value[key]})
        return True
