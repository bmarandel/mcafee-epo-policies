# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" mcafee_epo_policies Class """

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("mcafee_epo_policies")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["constants", "policies", "ma", "es", "sc"]

from .constants import State, Priority, Gti, OASState, Severity, Language, SCException, SCReputation
from .policies import Policies, Policy
from .ma.mapolicies import McAfeeAgentPolicies
from .ma.general import McAfeeAgentPolicyGeneral
from .ma.repository import McAfeeAgentPolicyRepository, RepositoryList
from .ma.troubleshooting import McAfeeAgentPolicyTroubleshooting
from .ma.customprops import McAfeeAgentPolicyCustomProps
from .ma.telemetry import McAfeeAgentPolicyTelemetry
from .es.tp.estppolicies import ESTPPolicies
from .es.tp.onaccessscan import ESTPPolicyOnAccessScan, OASProcessList, OASExclusionList, OASURLList
from .es.tp.ondemandscan import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList
from .es.tp.exploitprevention import ESTPPolicyExploitPrevention, SearchFilter
from .es.tp.options import ESTPPolicyOptions
from .es.tp.accessprotection import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
                                     APExecutable, APUserName)
from .es.fw.esfwpolicies import ESFWPolicies
from .es.fw.rules import ESFWPolicyRules
from .es.fw.options import ESFWPolicyOptions
from .sc.scpolicies import SCPolicies, SCPolicy
from .sc.rules import SCRules, SCExclusionRules, SCUpdaterRules
from .sc.gen import SCGENPolicyConfiguration, SCGENPolicyExceptionRules
from .sc.awl import SCAWLPolicyOptions, SCAWLPolicyRules
from .sc.cc import SCCCPolicyRules
from .sc.fim import SCFIMPolicyRules
from .sc.rulegroups import SCRuleGroups, SCRuleGroup, SCAWLRuleGroup, SCCCRuleGroup, SCFIMRuleGroup
