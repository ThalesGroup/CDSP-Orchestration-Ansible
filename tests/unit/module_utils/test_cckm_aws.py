#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cckm_aws.py

NOTE: This module imports POSTData/POSTWithoutData from cm_api which were
removed during the API client refactoring (Epic 3). These tests verify
that the import failure is detected. Once the CCKM modules are migrated
to use CipherTrustClient, this file should be updated with real tests.
"""

import pytest


class TestCCKMAWSImport:
    def test_import_fails_gracefully(self):
        """cckm_aws uses removed functions POSTData/POSTWithoutData from cm_api.
        This test documents the known broken import until migration."""
        with pytest.raises(ImportError):
            from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_aws import (
                performCKSOperation,
            )
