# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds shared support for generic Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
  module = ThalesCipherTrustModule(argument_spec=dictionary, supports_check_mode=boolean
                            mutually_exclusive=list1, required_together=list2)

The 'ThalesCipherTrustModule' module provides similar, but more restricted,
interfaces to the normal Ansible module.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


from contextlib import contextmanager

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CipherTrustError,
    CMApiException,
)


class ThalesCipherTrustModule:
    """An ansible module class for CipherTrust modules
    ThalesCipherTrustModule provides an a class for building modules which
    connect to Thales CipherTrust Manager.  The interface is currently more
    restricted than the basic module class with the aim that later the
    basic module class can be reduced.  If you find that any key
    feature is missing please create an issue on the GitHub repo for this collection.
    """

    default_settings = {
        "default_args": True,
        "auto_retry": True,
        "module_class": AnsibleModule,
    }

    def __init__(self, **kwargs):
        local_settings = {}
        for key in ThalesCipherTrustModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = ThalesCipherTrustModule.default_settings[key]

        self.settings = local_settings

        if local_settings["default_args"]:
            argument_spec_full = ciphertrust_argument_spec()
            try:
                argument_spec_full.update(kwargs["argument_spec"])
            except (TypeError, NameError):
                pass
            kwargs["argument_spec"] = argument_spec_full

        self._module = ThalesCipherTrustModule.default_settings["module_class"](
            **kwargs
        )
        self.check_mode = self._module.check_mode
        self._diff = self._module._diff
        self._name = self._module._name

    @property
    def params(self):
        return self._module.params

    def exit_json(self, *args, **kwargs):
        return self._module.exit_json(*args, **kwargs)

    def fail_json(self, *args, **kwargs):
        return self._module.fail_json(*args, **kwargs)

    def debug(self, *args, **kwargs):
        return self._module.debug(*args, **kwargs)

    def warn(self, *args, **kwargs):
        return self._module.warn(*args, **kwargs)

    def deprecate(self, *args, **kwargs):
        return self._module.deprecate(*args, **kwargs)

    def boolean(self, *args, **kwargs):
        return self._module.boolean(*args, **kwargs)


def _ciphertrust_common_argument_spec():
    """ """
    _node_params = dict(
        server_ip=dict(type="str", required=True),
        server_private_ip=dict(type="str", required=False, default='10.10.10.10'),
        server_port=dict(type="int", required=False, default=5432),
        user=dict(type="str", required=True),
        password=dict(type="str", required=True, no_log=True),
        verify=dict(type="bool", required=False, default=False),
        auth_domain_path=dict(type="str", required=False, default=''),
    )
    return dict(
        localNode=dict(
            type="dict",
            required=True,
            options=_node_params,
        )
    )


def ciphertrust_argument_spec():
    """
    Returns a dictionary containing the argument_spec common to all CipherTrust Manager modules.
    """
    spec = _ciphertrust_common_argument_spec()
    return spec


# ---------------------------------------------------------------------------
# Centralized error handling
# ---------------------------------------------------------------------------

def handle_module_error(module, exc):
    """Translate any collection-specific exception into a ``module.fail_json``.

    * ``CMApiException`` → includes the HTTP/application error code.
    * Any other ``CipherTrustError`` subclass → uses its composed ``message``.
    * Anything else → bubbles up as "Unexpected error: <repr>".
    """
    if isinstance(exc, CMApiException):
        code = getattr(exc, "api_error_code", None)
        if code:
            msg = "API Error (code: {0}): {1}".format(code, exc.message or "")
        else:
            msg = "API Error: {0}".format(exc.message or "")
    elif isinstance(exc, CipherTrustError):
        msg = exc.message or str(exc)
    else:
        msg = "Unexpected error: {0}".format(exc)
    module.fail_json(msg=msg)


@contextmanager
def ciphertrust_operation(module):
    """Context manager that catches every CipherTrust exception.

    Replaces the 70-line repeated ``try/except`` block that was present in
    every module.  Usage::

        with ciphertrust_operation(module):
            changed, response, diff = idempotent_create(...)
            result["changed"] = changed
            result["response"] = response

    Any raised :class:`CipherTrustError` (or subclass) triggers a clean
    ``module.fail_json`` via :func:`handle_module_error`.
    """
    try:
        yield
    except CipherTrustError as exc:
        handle_module_error(module, exc)
