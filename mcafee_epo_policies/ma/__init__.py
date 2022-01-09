# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" McAfee Agent Policies Class """

__all__ = ["mapolicies", "general", "repository"]

from .mapolicies import McAfeeAgentPolicies
from .general import McAfeeAgentPolicyGeneral
from .repository import McAfeeAgentPolicyRepository, RepositoryList