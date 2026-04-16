#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cckm_commons.py

NOTE: This module imports removed functions from cm_api (POSTData etc.).
See test_cckm_aws.py for explanation.
"""

import pytest


class TestCCKMCommonsImport:
    def test_import_fails_gracefully(self):
        """cckm_commons uses removed functions from cm_api."""
        with pytest.raises(ImportError):
            from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_commons import (
                addCCKMCloudAsset,
            )
