# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" mcafee_epo_policies Class """

import setuptools.version
__version__ = setuptools.version.__version__
__all__ = ["constants", "policies", "ma", "es"]

from .constants import State, Priority, Gti
from .policies import Policies, Policy
from .ma.mapolicies import McAfeeAgentPolicies
from .ma.general import McAfeeAgentPolicyGeneral
from .ma.repository import McAfeeAgentPolicyRepository, RepositoryList
from .es.tp.estppolicies import ESTPPolicies 
from .es.tp.onaccessscan import ESTPPolicyOnAccessScan, OASProcessList, OASExclusionList, OASURLList
from .es.tp.ondemandscan import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList
from .es.fw.esfwpolicies import ESFWPolicies
from .es.fw.rules import ESFWPolicyRules