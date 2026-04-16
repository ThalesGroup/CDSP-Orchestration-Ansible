#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cckm_azure.py

NOTE: This module imports removed functions from cm_api (POSTData etc.).
See test_cckm_aws.py for explanation.
"""

import pytest


class TestCCKMAzureImport:
    def test_import_fails_gracefully(self):
        """cckm_azure uses removed functions from cm_api."""
        with pytest.raises(ImportError):
            from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_azure import (
                performAZKeyVaultOperation,
            )
