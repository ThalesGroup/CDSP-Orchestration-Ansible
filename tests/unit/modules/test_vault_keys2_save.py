#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock

# The module is imported for mocking
from ansible_collections.thalesgroup.ciphertrust.plugins.modules import vault_keys2_save

def test_check_mode(mock_module):
    mock_module.check_mode = True
    # TODO

def test_create(mock_module):
    pass

def test_patch_idempotent(mock_module):
    pass
