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

class Severity():
    """
    Severity constants can be used with Endpoint Security, Threat Prevention Exploit Prevention policy
        '0' = DISABLED
        '1' = INFORMATIONAL
        '2' = LOW
        '3' = MEDIUM
        '4' = HIGH
    """
    DISABLED, INFORMATIONAL, LOW, MEDIUM, HIGH = ['{}'.format(r) for r in range(5)]

class Language():
    """
    Language constants can be used with McAfee Agent, Troubleshooting policy
    (agent_language property) instead of remembering the raw Windows LCID hex
    code shown in the "Select language used by agent" dropdown.

    Only UI_DEFAULT ('0000') and ENGLISH ('0409') have been confirmed against
    real ePO exports so far. The rest follow the standard Windows LCID table
    for the language names listed in that dropdown but have not been
    individually confirmed - please report any mismatch you notice.
    """
    UI_DEFAULT = '0000'
    CHINESE_SIMPLIFIED = '0804'
    CHINESE_TRADITIONAL = '0404'
    CZECH = '0405'
    DANISH = '0406'
    DUTCH = '0413'
    ENGLISH = '0409'
    FINNISH = '040B'
    FRENCH = '040C'
    GERMAN = '0407'
    ITALIAN = '0410'
    JAPANESE = '0411'
    KOREAN = '0412'
    NORWEGIAN = '0414'
    POLISH = '0415'
    PORTUGUESE = '0816'
    PORTUGUESE_BRAZILIAN = '0416'
    RUSSIAN = '0419'
    SPANISH = '040A'
    SWEDISH = '041D'
    TURKISH = '041F'
