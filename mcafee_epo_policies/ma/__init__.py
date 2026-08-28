# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" McAfee Agent Policies Class """

__all__ = ["mapolicies", "general", "repository", "troubleshooting", "customprops", "telemetry"]

from .mapolicies import McAfeeAgentPolicies
from .general import McAfeeAgentPolicyGeneral
from .repository import McAfeeAgentPolicyRepository, RepositoryList
from .troubleshooting import McAfeeAgentPolicyTroubleshooting
from .customprops import McAfeeAgentPolicyCustomProps
from .telemetry import McAfeeAgentPolicyTelemetry