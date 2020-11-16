# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ExclusionList for On-Access and On-Demand policies.
"""

class ExclusionList:
    """
    The ExclusionList class can be used to edit the list of exclusion.
    What to exclude:
    '0': File age, changed with Minimum age in days
    '1': ? (not used or deprecated)
    '2': File age, created with Minimum age in days
    '3': File name or path (can include * or ? wildcards)
    '4': File type (can include the ? wildcard)

    When to excluded:
    1: On Write
    2: On Read
    4: Also exclude subfolders
    -> The final value is and addition of all options

    Name: File name or path, extension or days.

    Notes: Notes of the exclusion
    """

    def __init__(self, exclusion_list = list()):
        self.excl_list = exclusion_list

    def __repr__(self):
        return '<ExclusionList which contains {} exclusion(s)>'.format(len(self.excl_list))

    def __define_item__(self, action, value):
        item = ''
        if action == '0':
            item = 'Modified {} or more days ago'.format(value)
        elif action == '2':
            item = 'Created {} or more days ago'.format(value)
        elif action == '3':
            item = value
        elif action == '4':
            item = 'All files of type {}'.format(value)
        else:
            item = 'Unknown item'
        return item

    def __define_rights__(self, int_rights, action):
        rights = int_rights-4
        if rights >= 0:
            sub = True
        else:
            rights = rights+4
            sub = False
        rights = rights-2
        if rights >=0:
            read = True
        else:
            rights = rights+2
            read = False
        rights = rights-1
        write = bool(rights >= 0)

        if read and write:
            when = 'Read & Write'
        elif write:
            when = 'Write'
        else:
            when = 'Read'

        if action != '3':
            subfolder = '--'
        else:
            if sub:
                subfolder = 'Yes'
            else:
                subfolder = 'No'

        return (subfolder, when)

    def __compute_rights__(self, write, read, subfolder=False):
        rights = 0
        if write:
            rights = rights+1
        if read:
            rights = rights+2
        if subfolder:
            rights = rights+4
        return rights

    def __str__(self):
        txt = '| {0:70}| {1:12}| {2:13}| {3:30}|\n'.format(
              'Item:', 'Subfolders:', 'When:', 'Notes:')
        txt += '|:----------------------------------------------------------------------|'
        txt += ':------------|:-------------|:------------------------------|'
        for row in self.excl_list:
            item = self.__define_item__(row[0], row[2])
            rights = self.__define_rights__(int(row[1]), row[0])
            subfolder = rights[0]
            when = rights[1]
            notes = row[3]
            txt += '\n| {0:70}| {1:12}| {2:13}| {3:30}|'.format(item, subfolder, when, notes)
        return txt

    def __add_excl__(self, what, int_when, value, notes):
        if what not in ['0', '2', '3', '4']:
            raise ValueError('What to excluded value must be within ["0", "2", "3", "4"].')
        if int_when < 0 or int_when > 7:
            raise ValueError('When to excluded value must be within [0-7].')
        exclusion = []
        exclusion.append(what)
        exclusion.append(str(int_when))
        exclusion.append(value)
        exclusion.append(notes)
        self.excl_list.append(exclusion)
        return True

    def __contains_excl__(self, what, value):
        search = [row for row in self.excl_list if row[0] == what and row[2] == value]
        return len(search) >= 1

    def __remove__(self, what, value):
        table = [row for row in self.excl_list if not (row[0] == what and row[2] == value)]
        self.excl_list = table
        return True

    def add_folder(self, folder_path, on_write=True, on_read=True, with_subfolders=False, notes=''):
        """
        Add a folder exclusion
        """
        if folder_path[len(folder_path)-1] != '\\':
            raise ValueError('Path must be ended by "\\".')
        rights = self.__compute_rights__(on_write, on_read, with_subfolders)
        return self.__add_excl__('3', rights, folder_path, notes)

    def add_file_name(self, file_name_path, on_write=True, on_read=True, notes=''):
        """
        Add a file name exclusion
        """
        if file_name_path[len(file_name_path)-1] == '\\':
            raise ValueError('Path must not be ended by "\\".')
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('3', rights, file_name_path, notes)

    def add_file_type(self, file_extension, on_write=True, on_read=True, notes=''):
        """
        Add a file type exclusion
        """
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('4', rights, file_extension, notes)

    def add_file_modified(self, int_days=7, on_write=True, on_read=True, notes=''):
        """
        Add a file exclusion based on its last modified date
        """
        if int_days < 1:
            raise ValueError('Need one or more days.')
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('0', rights, str(int_days), notes)

    def add_file_created(self, int_days=7, on_write=True, on_read=True, notes=''):
        """
        Add a file exclusiopn based on its created date
        """
        if int_days < 1:
            raise ValueError('Need one or more days.')
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('2', rights, str(int_days), notes)

    def contains_folder(self, folder_path):
        """
        Returns True if a folder is excluded
        """
        return self.__contains_excl__('3', folder_path)

    def contains_file_name(self, file_name_path):
        """
        Returns True if a file name is excluded
        """
        return self.__contains_excl__('3', file_name_path)

    def contains_file_type(self, file_extension):
        """
        Returns True if a file extension is excluded
        """
        return self.__contains_excl__('4', file_extension)

    def contains_file_modified(self, int_days):
        """
        Returns True is a file is excluded based on its last modified date
        """
        return self.__contains_excl__('0', str(int_days))

    def contains_file_created(self, int_days):
        """
        Returns True is a file is excluded based on its created date
        """
        return self.__contains_excl__('2', str(int_days))

    def remove_folder(self, folder_path):
        """
        Remove a folder exclusion
        """
        return self.__remove__('3', folder_path)

    def remove_file_name(self, file_name_path):
        """
        Remove a file name exclusion
        """
        return self.__remove__('3', file_name_path)

    def remove_file_type(self, file_extension):
        """
        Remove a file extension exclusion
        """
        return self.__remove__('4', file_extension)

    def remove_file_modified(self, int_days):
        """
        Remove a file exclusion based on its last modified date
        """
        return self.__remove__('0', str(int_days))

    def remove_file_created(self, int_days):
        """
        Remove a file exclusion based on its created date
        """
        return self.__remove__('2', str(int_days))
