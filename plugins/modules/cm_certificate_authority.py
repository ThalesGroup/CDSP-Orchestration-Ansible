#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.ca import (
    createLocalCA,
    updateLocalCA,
    selfSign,
    issueCertificate,
    revokeCert,
    resumeCert,
    createCSR,
    createCSRAndKey,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

DOCUMENTATION = """
---
module: cm_certificate_authority
short_description: Create and manage CipherTrust Manager Local CA
description:
    - Create and edit local Certificate Authority on CipherTrust Manager
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    localNode:
      description:
        - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
        - holds IP/FQDN of the server, username, password, and port 
      required: true
      type: dict
      suboptions:
        server_ip:
          description: CM Server IP or FQDN
          type: str
          required: true
        server_private_ip:
          description: internal or private IP of the CM Server, if different from the server_ip
          type: str
          required: true
        server_port:
          description: Port on which CM server is listening
          type: int
          required: true
          default: 5432
        user:
          description: admin username of CM
          type: str
          required: true
        password:
          description: admin password of CM
          type: str
          required: true
        verify:
          description: if SSL verification is required
          type: bool
          required: true
          default: false
        auth_domain_path:
          description: user's domain path
          type: str
          required: true  
    op_type:
      description: Operation to be performed
      choices: [create, patch, issue-cert, self-sign, revoke-cert, resume-cert, create-csr, create-csr-key]
      required: true
      type: str
    cn:
      description: Common Name
      type: str
    algorithm:
      description: RSA or ECDSA (default) algorithms are supported. Signature algorithm (SHA512WithRSA, SHA384WithRSA, SHA256WithRSA, SHA1WithRSA, ECDSAWithSHA512, ECDSAWithSHA384, ECDSAWithSHA256) is selected based on the algorithm and size.
      type: str
    dnsNames:
      description: Subject Alternative Names (SAN) values
      type: str
    emailAddresses:
      description: E-mail addresses
      type: str
    ipAddresses:
      description: IP addresses
      type: str
    name:
      description: A unique name of CA, if not provided, will be set to localca-<id>.
      type: str
    names:
      description: Name fields
      type: list
    size:
      description: CSR in PEM format
      type: str
    allow_client_authentication:
      description: If set to true, the certificates signed by the specified CA can be used for client authentication.
      type: bool
    allow_user_authentication:
      description: If set to true, the certificates signed by the specified CA can be used for user authentication.
      type: bool
    csr:
      description: CSR in PEM format
      type: str
    purpose:
      description: server, client or ca
      type: str
    duration:
      description: Duration in days of certificate. Either duration or notAfter date must be specified.
      type: int
    notAfter:
      description: End date of certificate. Either notAfter or duration must be specified. notAfter overrides duration if both are given.
      type: str
    notBefore:
      description: Start date of certificate
      type: str
    reason:
      description: Specify one of the reason.
      choices: [unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise]
      type: str
    csrParams:
      description: Parameters to be used during creating CSR like the subject, x509 extensions and signature algorithm used.
      type: dict
    keyGenParams:
      description: Parameters to be used for creating an asymmetric key to be used for CSR creation.
      type: dict
    keyID:
      description: Type of the identifier, keyID, for the private key to be used for creating CSR.
      type: str
    keyIDType:
      description: Parameters to be used for creating an asymmetric key to be used for CSR creation.
      type: str
    keyVersion:
      description: Version of the private key, keyID, to be used for creating CSR.
      type: int
    encryptionAlgo:
      description: Private key encryption algorithm.
      choices: [AES256, AES192, AES128, TDES]
      type: str
    password:
      description: Password to PEM-encrypt the private key. If not specified, the private key is not encrypted in return.
      type: str
    privateKeyBytes:
      description: Private Key bytes of the key which is to be used while creating CSR(Algorithm and size should be according to this key). If not given will generate key internally as per algorithm and size.
      type: str
"""

EXAMPLES = '''
- name: "Create CM Local CA"
  thalesgroup.ciphertrust.cm_certificate_authority:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    cn: local_ca_ansible
    name: AnsibleLocalCA
    algorithm: RSA
    size: 4096
    names:
      - C: CA
        ST: ontario
        L: ottawa
        O: ciphertrust
        OU: test
  register: ca

- name: Self sign the CA
  thalesgroup.ciphertrust.cm_certificate_authority:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: self-sign
    id: "{{ ca['response']['id'] }}"
    duration: 365

- name: Create CSR
  thalesgroup.ciphertrust.cm_certificate_authority:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create-csr-key
    cn: csr
    name: AnsibleCSR
    algorithm: RSA
    size: 2048
    ipAddresses:
      - 10.1.1.10
    names:
      - C: CA
        ST: ontario
        L: ottawa
        O: ciphertrust
        OU: test
    encryptionAlgo: AES256
  register: csr

- name: Issue Certificate
  thalesgroup.ciphertrust.cm_certificate_authority:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: issue-cert
    id: "{{ ca['response']['id'] }}"
    csr: "{{ csr['response']['data']['csr'] }}"
    purpose: server
    duration: 365
    name: AnsibleServerCert
  register: cert
'''

RETURN = """

"""

_name = dict(
  C=dict(type='int'),
  L=dict(type='str'),
  O=dict(type='str'),
  OU=dict(type='int'),
  ST=dict(type='str'),
)

_csr_params = dict(
  cn=dict(type='str'),
  dnsNames=dict(type='list', element='str'),
  emailAddresses=dict(type='list', element='str'),
  extendedKeyUsage=dict(type='list', element='str'),
  ipAddresses=dict(type='list', element='str'),
  isCA=dict(type='bool'),
  keyUsage=dict(type='list', element='str'),
  maxPathLen=dict(type='int'),
  names=dict(type='list', element='dict', options=_name),
  signatureAlgorithm=dict(type='str', choices=['sha512WithRSA', 'sha384WithRSA', 'sha256WithRSA', 'sha1WithRSA', 'ecdsaWithSHA512', 'ecdsaWithSHA384', 'ecdsaWithSHA256', 'ecdsaWithSHA1']),
  subjectKeyIdentifierHash=dict(type='bool'),
)

_keyGenParams = dict(
  algorithm=dict(type='str', choices=['RSA', 'EC'], default='RSA'),
  curveid=dict(type='str', choices=['secp224r1', 'secp384r1', 'secp521r1', 'prime256v1']),
  keyName=dict(type='str'),
  size=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', choices=[
      'create', 
      'patch',
      'issue-cert',
      'self-sign',
      'revoke-cert',
      'resume-cert',
      'create-csr',
      'create-csr-key',
    ], required=True),
    id=dict(type='str'),
    cert_id=dict(type='str'),
    # Add local CA
    cn=dict(type='str'),
    algorithm=dict(type='str', choices=['RSA', 'ECDSA']),
    dnsNames=dict(type='list', element='str'),
    emailAddresses=dict(type='list', element='str'),
    ipAddresses=dict(type='list', element='str'),
    name=dict(type='str'),
    names=dict(type='list', element='dict', options=_name),
    size=dict(type='int'),
    # Update local CA
    allow_client_authentication=dict(type='bool'),
    allow_user_authentication=dict(type='bool'),
    # Issue cert from Local CA
    csr=dict(type='str'),
    purpose=dict(type='str', choices=['server', 'client', 'ca']),
    duration=dict(type='int'),
    notAfter=dict(type='str'),
    notBefore=dict(type='str'),
    # Revoke Cert
    reason=dict(type='int', choices=['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise']),
    # Create CSR
    csrParams=dict(type='dict', options=_csr_params),
    keyGenParams=dict(type='dict', options=_keyGenParams),
    keyID=dict(type='str'),
    keyIDType=dict(type='str'),
    keyVersion=dict(type='int'),
    # create CSR with Key
    encryptionAlgo=dict(type='str', choices=['AES256', 'AES192', 'AES128', 'TDES']),
    password=dict(type='str'),
    privateKeyBytes=dict(type='str'),
)


def validate_parameters(cm_certificate_authority):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['cn']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'self-sign', ['id']],
            ['op_type', 'issue-cert', ['id', 'csr', 'purpose']],
            ['op_type', 'revoke-cert', ['id', 'cert_id', 'reason']],
            ['op_type', 'resume-cert', ['id', 'cert_id']],
            ['op_type', 'create-csr-key', ['cn']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        cm_certificate_authority=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createLocalCA(
          node=module.params.get('localNode'),
          cn=module.params.get('cn'),
          algorithm=module.params.get('algorithm'),
          dnsNames=module.params.get('dnsNames'),
          emailAddresses=module.params.get('emailAddresses'),
          ipAddresses=module.params.get('ipAddresses'),
          name=module.params.get('name'),
          names=module.params.get('names'),
          size=module.params.get('size'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateLocalCA(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          allow_client_authentication=module.params.get('allow_client_authentication'),
          allow_user_authentication=module.params.get('allow_user_authentication'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'self-sign':
      try:
        response = selfSign(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          duration=module.params.get('duration'),
          notAfter=module.params.get('notAfter'),
          notBefore=module.params.get('notBefore'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'issue-cert':
      try:
        response = issueCertificate(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          csr=module.params.get('csr'),
          purpose=module.params.get('purpose'),
          duration=module.params.get('duration'),
          name=module.params.get('name'),
          notAfter=module.params.get('notAfter'),
          notBefore=module.params.get('notBefore'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'revoke-cert':
      try:
        response = revokeCert(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          cert_id=module.params.get('cert_id'),
          reason=module.params.get('reason'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'resume-cert':
      try:
        response = resumeCert(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          cert_id=module.params.get('cert_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-csr':
      try:
        response = createCSR(
          node=module.params.get('localNode'),
          csrParams=module.params.get('csrParams'),
          keyGenParams=module.params.get('keyGenParams'),
          keyID=module.params.get('keyID'),
          keyIDType=module.params.get('keyIDType'),
          keyVersion=module.params.get('keyVersion'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'create-csr-key':
      try:
        response = createCSRAndKey(
          node=module.params.get('localNode'),
          cn=module.params.get('cn'),
          algorithm=module.params.get('algorithm'),
          dnsNames=module.params.get('dnsNames'),
          emailAddresses=module.params.get('emailAddresses'),
          ipAddresses=module.params.get('ipAddresses'),
          name=module.params.get('name'),
          names=module.params.get('names'),
          size=module.params.get('size'),
          encryptionAlgo=module.params.get('encryptionAlgo'),
          privateKeyBytes=module.params.get('privateKeyBytes'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)


if __name__ == "__main__":
    main()
