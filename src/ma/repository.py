# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class McAfeeAgentPolicyRepository and RepositoryList.
"""

import xml.etree.ElementTree as et
from ..policies import Policy

class McAfeeAgentPolicyRepository(Policy):
    """
    The McAfeeAgentPolicyRepository class can be used to edit the McAfee Agent policy: Repository.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(McAfeeAgentPolicyRepository, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'Repository':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "Repository".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<McAfeeAgentPolicyRepository for policy {} from server {}.>'.format(name, epo)

    def get_site_list(self):
        """
        Get a table (list of list) of sites within the Repository policy
        """
        table = None
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="InetManager"]')
        if section_obj is not None:
            # If there are some disabled sites, build a list of
            disabled_sites = []
            setting_obj = section_obj.find('Setting[@name="DisabledSiteNum"]')
            if setting_obj is not None:
                max_rows = int(setting_obj.get('value'))
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="DisabledSites_{}"]'.format(row))
                    disabled_sites.append(setting_obj.get('value'))
            setting_obj = section_obj.find('Setting[@name="SitelistOrderNum"]')
            max_rows = int(setting_obj.get('value'))
            table = []
            for row in range(max_rows):
                row_value = []
                setting_obj = section_obj.find('Setting[@name="SitelistOrder_{}"]'.format(row))
                row_value.append(setting_obj.get('value'))
                if row_value[0] in disabled_sites:
                    row_value.append('Disabled')
                else:
                    row_value.append('Enabled')
                table.append(row_value)
        return table

    def set_site_list(self, table):
        """
        Set a table (list of list) of sites within the Repository policy
        """
        success = False
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="InetManager"]')
        if section_obj is not None:
            success = True
            parent_obj = self.root.find('./EPOPolicySettings')
            parent_obj.remove(section_obj)
            section_obj = et.SubElement(parent_obj, 'Section', name='InetManager')
            # Determine if there are some disabled sites
            disabled_sites = [row[0] for row in table if row[1] == 'Disabled']
            if disabled_sites:
                et.SubElement(section_obj,
                              'Setting',
                              {"name":'DisabledSiteNum', "value":str(len(disabled_sites))})
                for index, site in enumerate(disabled_sites):
                    et.SubElement(section_obj,
                                  'Setting',
                                  {"name":'DisabledSites_{}'.format(index), "value":site})
            # Add all sites
            sites = [row[0] for row in table]
            if sites:
                et.SubElement(section_obj,
                              'Setting',
                              {"name":'SitelistOrderNum', "value":str(len(sites))})
                for index, site in enumerate(sites):
                    et.SubElement(section_obj,
                                  'Setting',
                                  {"name":'SitelistOrder_{}'.format(index), "value":site})
        return success

class RepositoryList():
    """
    The RepositoryList class can be used to edit the repository list from the policy.
    """

    def __init__(self, repository_list=None):
        if repository_list is None:
            self.repo_list = []
        else:
            self.repo_list = repository_list
        self.__update_index__()

    def __repr__(self):
        return '<RepositoryList which contains {} site(s)>'.format(len(self.repo_list))

    def __str__(self):
        txt = '| {0:5} | {1:25}| {2:9}|\n'.format('Order', 'Name', 'State')
        txt += '|------:|:-------------------------|:---------|'
        for index, row in enumerate(self.repo_list):
            txt += '\n| {0:5} | {1:25}| {2:9}|'.format(index, row[0], row[1])
        return txt

    def __update_index__(self):
        self.repo_index = [r[0] for r in self.repo_list]
    
    def is_empty(self):
        """
        Return True if the RepositoryList is empty.
        """
        return self.repo_list.count(0) == 0

    def add(self, site_name, state='Disabled'):
        """
        Add a site with its state to the RepositoryList
        """
        self.repo_list.append([site_name, state])
        self.__update_index__()

    def remove(self, site_name):
        """
        Remove a site with its state to the RepositoryList
        """
        row_index = self.repo_index.index(site_name)
        self.repo_list.pop(row_index)
        self.__update_index__()

    def index(self, site_name):
        """
        Return the current index of the site within the RepositoryList
        """
        try:
            return self.repo_index.index(site_name)
        except ValueError:
            return -1

    def contain(self, site_name):
        """
        Return True if the RepositoryList contains the site
        """
        index = self.repo_index.index(site_name)
        return index > -1

    def state(self, site_name):
        """
        Return the current state of the site
        """
        return self.repo_list[self.repo_index.index(site_name)][1]

    def set_repo_list(self, table):
        """
        Set the list of repositories
        """
        self.repo_list = table
        self.__update_index__()

    def get_repo_list(self):
        """
        Get the list of repositories
        """
        return self.repo_list

    def enable(self, site_name):
        """
        Enable a repository site based on his name
        """
        self.repo_list[self.repo_index.index(site_name)][1] = 'Enabled'

    def disable(self, site_name):
        """
        Disable a repository site based on his name
        """
        self.repo_list[self.repo_index.index(site_name)][1] = 'Disabled'

    def move_at(self, site_name, new_index):
        """
        Move a site to a soecific index
        """
        row_index = self.repo_index.index(site_name)
        if new_index in range(len(self.repo_list)+1):
            self.repo_list.insert(new_index, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_up(self, site_name):
        """
        Move Up a site
        """
        row_index = self.repo_index.index(site_name)
        if row_index in range(1, len(self.repo_list)+1):
            self.repo_list.insert(row_index-1, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_down(self, site_name):
        """
        Move Down a site
        """
        row_index = self.repo_index.index(site_name)
        if row_index in range(len(self.repo_list)):
            self.repo_list.insert(row_index+1, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_top(self, site_name):
        """
        Move at the top a repository site based on his name
        """
        self.move_at(site_name, 0)

    def move_bottom(self, site_name):
        """
        Move at the bottom a repository site based on his name
        """
        self.move_at(site_name, len(self.repo_list))
