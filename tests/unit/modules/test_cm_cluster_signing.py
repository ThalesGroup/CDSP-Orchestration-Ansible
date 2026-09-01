# -*- coding: utf-8 -*-
"""The cluster join flow parses a payload that CipherTrust Manager builds.

``description`` arrives as a string that has to be parsed before the join
request can be assembled. It used to go straight through ``ast.literal_eval``
with the resulting keys read unguarded, so an unexpected response killed the
module with ``ValueError`` or ``KeyError`` mid-way through a cluster join.
"""

import importlib
import json

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)

cm_cluster = importlib.import_module(
    "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_cluster"
)
_parse = cm_cluster._parse_signing_response

PAYLOAD = {"cert": "CERT", "cachain": "CHAIN", "mkek_blob": "BLOB"}


class TestAcceptedShapes:

    def test_json_payload(self):
        assert _parse({"description": json.dumps(PAYLOAD)}) == PAYLOAD

    def test_python_literal_payload(self):
        """Older CM releases returned a Python-style dict literal."""
        assert _parse({"description": str(PAYLOAD)}) == PAYLOAD


class TestRejectedShapes:

    @pytest.mark.parametrize("output,fragment", [
        ({}, "no 'description'"),
        ({"description": None}, "no 'description'"),
        ("not a dict", "no 'description'"),
        ({"description": "<html>error</html>"}, "Could not parse"),
        ({"description": "[1, 2, 3]"}, "expected a mapping"),
    ])
    def test_bad_payload_becomes_an_api_error(self, output, fragment):
        with pytest.raises(CMApiException, match=fragment):
            _parse(output)

    def test_missing_fields_are_named(self):
        with pytest.raises(CMApiException, match="cachain"):
            _parse({"description": json.dumps({"cert": "CERT"})})
