# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    """Shared documentation for CipherTrust Manager connection parameters.

    All modules in this collection connect to a CipherTrust Manager instance
    through the ``localNode`` dict.  Instead of copying the same 25 lines of
    suboption documentation into every module, they use::

        extends_documentation_fragment:
          - thalesgroup.ciphertrust.ciphertrust
    """

    DOCUMENTATION = r"""
options:
  localNode:
    description:
      - Connection parameters for the CipherTrust Manager (CM) instance.
      - Holds IP/FQDN, port, admin credentials, and TLS-verification flag.
      - The C(password) sub-option is redacted from Ansible logs
        (C(no_log=True)).
      - Set C(verify) to C(true) in production to enable TLS certificate
        validation. It defaults to C(false) for backwards compatibility
        with lab environments using self-signed certificates.
    required: true
    type: dict
    suboptions:
      server_ip:
        description: IP address or FQDN of the CipherTrust Manager.
        type: str
        required: true
      server_private_ip:
        description:
          - Internal/private IP of the CM Server, if different from
            C(server_ip).
          - Used for cluster node-to-node communication.
        type: str
        required: false
        default: 10.10.10.10
      server_port:
        description: Port on which CipherTrust Manager is listening.
        type: int
        required: false
        default: 5432
      user:
        description: CipherTrust Manager admin username.
        type: str
        required: true
      password:
        description:
          - CipherTrust Manager admin password.
          - Redacted from Ansible logs.
          - Recommended to supply via Ansible Vault or an external secret
            store rather than plaintext in playbooks.
        type: str
        required: true
      verify:
        description:
          - Whether to verify the CM server's TLS certificate.
          - Set to C(true) in production.
        type: bool
        required: false
        default: false
      auth_domain_path:
        description:
          - Optional authentication domain path.
          - Leave empty for the root domain.
        type: str
        required: false
        default: ''
"""
