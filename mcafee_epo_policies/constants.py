# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines CONSTANTES to use with mcafee_epo_policies Class
"""

class State():
    """
    State constants can be used with all policies to change the state of an option
    """
    VISIBLE = '1'
    HIDDEN = '0'
    ENABLED = '1'
    DISABLED = '0'

class Priority():
    """
    Priority constants can be used with McAfee Agent, General policy
        '0' = INFORMATIONAL
        '1' = WARNING
        '2' = MINOR
        '3' = MAJOR
        '4' = CRITICAL
    """
    INFORMATIONAL, WARNING, MINOR, MAJOR, CRITICAL = ['{}'.format(r) for r in range(5)]

class Gti():
    """
    GTI constants can be used with Endpoint Security, Threat Prevention OAS policy
        '0' = DISABLED
        '1' = VERY_LOW
        '2' = LOW
        '3' = MEDIUM
        '4' = HIGH
        '5' = VERY_HIGH
    """
    DISABLED, VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH = ['{}'.format(r) for r in range(6)]
