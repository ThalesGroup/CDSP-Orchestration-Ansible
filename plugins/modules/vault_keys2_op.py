#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: vault_keys2_op
short_description: Perform operations on keys
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with key operations API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    key_version:
        description:
          - Query Parameter
          - Key version
          - Defaults to the latest version
          - Valid only if id_type is "name"
        required: false
        type: int
    id_type:
        description:
          - Query Parameter
          - Type of identifier for the key
        required: false
        choices: ['name', 'id', 'uri', 'alias']
        type: str
    include_material:
        aliases: [includeMaterial]
        description:
          - Query Parameter
          - weather to include the key material if the op_type is clone
          - applicable only if op_type is clone
        required: false
        type: bool
        default: false
    op_type:
        description: Operation to be performed
        choices: ['destroy', 'archive', 'recover', 'revoke', 'reactivate', 'export', 'clone']
        required: true
        type: str
    cm_key_id:
        description:
          - CM ID of the key that needs to be patched.
        type: str
        required: true
        default: null
    reason:
        description:
          - If the reason the key is being revoked, choices are
          - Unspecified
          - KeyCompromise
          - CACompromise
          - AffiliationChanged
          - Superseded
          - CessationOfOperation
          - PrivilegeWithdrawn
          - If the reason the key is being reactivated, choices are
          - DeactivatedToActive
          - ActiveProtectStopToActive
          - DeactivatedToActiveProtectStop
          - Required if op_type is either revoke or reactivate
        type: str
        choices:
          - Unspecified
          - KeyCompromise
          - CACompromise
          - AffiliationChanged
          - Superseded
          - CessationOfOperation
          - PrivilegeWithdrawn
          - DeactivatedToActive
          - ActiveProtectStopToActive
          - DeactivatedToActiveProtectStop
        default: null
    compromise_occurrence_date:
        aliases: [compromiseOccurrenceDate]
        description:
          - Date/time when the object was first believed to be compromised, if known.
          - Only valid if the revocation reason is CACompromise or KeyCompromise, otherwise ignored.
          - Defaults to key''s creation time.
        type: str
        required: false
        default: null
    message_str:
        aliases: [messageStr]
        description:
          - Message explaining revocation.
          - Message explaining reactivation.
        type: str
        required: false
        default: null
    combine_xts:
        aliases: [combineXts]
        description:
          - If set to true, then full material of XTS/CBC-CS1 key will be exported.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    encoding:
        description:
          - Specifies the encoding used for the material field.
          - For wrapping scenarios and PKCS12 format, the only valid option is base64.
          - In case of "Symmetric Keys" when format parameter has base64 value and encoding parameter also contains some value.
          - The encoding parameter takes the priority.
          - Options for Symmetric Keys are hex or base64
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    key_format:
        aliases: [keyFormat]
        description:
          - The format of the returned key material
        type: str
        choices: [pkcs1, pkcs8, pkcs12, jwe]
        required: false
        default: null
    mac_sign_key_identifier:
        aliases: [macSignKeyIdentifier]
        description:
          - This parameter specifies the identifier of the key used for generating the MAC or signature of the key whose key material is to be exported
          - The "wrappingMethod" should be "mac/sign" to generate the MAC/signature.
          - To generate a MAC, the key should be a HMAC key.
          - To generate a signature, the key should be an RSA private key.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    mac_sign_key_identifier_type:
        aliases: [macSignKeyIdentifierType]
        description:
          - This parameter specifies the identifier of the key("macSignKeyIdentifier") used for generating MAC or signature of the key material.
          - The "wrappingMethod" should be "mac/sign" to verify the mac/signature("macSignBytes") of the key material("material")
          - Only applicable for op_type "export"
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    padded:
        description:
          - This parameter determines the padding for the wrap algorithm while exporting a symmetric key
          - If true, the RFC 5649(AES Key Wrap with Padding) is followed and
          - If false, RFC 3394(AES Key Wrap) is followed for wrapping the material for the symmetric key.
          - If a certificate is being exported with the "wrappingMethod" set to "encrypt", the "padded" parameter must be set to true.
          - This parameter defaults to false.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    password:
        description:
          - For pkcs12 format, if the pkcs12passwordLink is not present in the Key (RSA keys), specify either password or secretDataLink.
          - This should be the base64 encoded value of the password.
          - Only applicable for op_type "export"
        type: str
        default: null
        required: false
    pem_wrap:
        aliases: [pemWrap]
        description:
          - If the parameter is set to true, it wraps the PEM encoding of the private key (asymmetric) otherwise, the DER encoding of the key is wrapped.
          - Only valid when private keys (asymmetric) and certificates are to be wrapped for "mac/sign" and "encrypt" values for "wrappingMethod" parameter.
          - This parameter defaults to false.
          - Only applicable for op_type "export"
        type: bool
        default: false
        required: false
    secret_data_encoding:
        aliases: [secretDataEncoding]
        description:
          - For pkcs12 format, this field specifies the encoding method used for the secretDataLink material
          - Ignore this field if secretData is created from REST and is in plain format
          - Specify the value of this field as HEX format if secretData is created from KMIP.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    secret_data_link:
        aliases: [secretDataLink]
        description:
          - For pkcs12 format, either secretDataLink or password should be specified
          - The value can be either ID or name of Secret Data.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    signing_algo:
        aliases: [signingAlgo]
        description:
          - This parameter specifies the algorithm to be used for generating the signature for the verification of
          - macSignBytes during import of key material
          - The "wrappingMethod" should be "mac/sign" to verify the signature("macSignBytes") of the key material("material")
          - Only applicable for op_type "export"
        choices: [RSA, RSA-PSS]
        type: str
        required: false
        default: null
    wrap_hkdf:
        aliases: [wrapHKDF]
        description:
          - Information which is used to wrap a Key using HKDF.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          hash_algorithm:
            aliases: [hashAlgorithm]
            description: Hash Algorithm is used for HKDF Wrapping.
            type: str
            choices: [hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512]
            required: false
            default: null
          info:
            description: Info is an optional hex value for HKDF based derivation.
            type: str
            required: false
            default: null
          okm_len:
            aliases: [okmLen]
            description: The desired output key material length in integer.
            type: int
            required: false
            default: null
          salt:
            description: Salt is an optional hex value for HKDF based derivation.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrap_jwe:
        aliases: [wrapJWE]
        description:
          - Information which is used to wrap a Key using JWE
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          content_encryption_algorithm:
            aliases: [contentEncryptionAlgorithm]
            description:
              - Content Encryption Algorithm is symmetric encryption algorithm used to encrypt the data
              - default is AES_256_GCM.
            type: str
            choices: [AES_128_CBC_HMAC_SHA_256, AES_192_CBC_HMAC_SHA_384, AES_256_CBC_HMAC_SHA_512, AES_128_GCM, AES_192_GCM, AES_256_GCM]
            required: false
            default: AES_256_GCM
          jwt_identifier:
            aliases: [jwtIdentifier]
            description: JWT identifier (JTI) is unique identifier for the JWT used by SFDC for cache key replay detection.
            type: str
            required: false
            default: null
          key_encryption_algorithm:
            aliases: [keyEncryptionAlgorithm]
            description:
              - Key Encryption Algorithm is used to encrypt the Content Encryption Key (CEK), default is RSA_OAEP_SHA1
              - Algorithm should correspond to type of public key provided for wrapping.
            type: str
            choices: [RSA1_5, RSA_OAEP_SHA1, RSA_OAEP_SHA256, ECDH_ES, ECDH_ES_AES_128_KEY_WRAP, ECDH_ES_AES_192_KEY_WRAP, ECDH_ES_AES_256_KEY_WRAP]
            default: RSA_OAEP_SHA1
            required: false
          key_identifier:
            aliases: [keyIdentifier]
            description: Key identifier to be used as "kid" parameter in JWE material and JWE header. Defaults to key id.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrap_key_id_type:
        aliases: [wrapKeyIDType]
        description:
          - IDType specifies how the wrapKeyName should be interpreted.
          - Only applicable for op_type "export"
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    wrap_key_name:
        aliases: [wrapKeyName]
        description:
          - The key material will be wrapped with material of the specified key name
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrap_pbe:
        aliases: [wrapPBE]
        description:
          - WrapPBE produces a derived key from a password and other parameters
          - PBE is currently only supported to wrap symmetric keys (AES), private Keys and certificates.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          hash_algorithm:
            aliases: [hashAlgorithm]
            description: Underlying hashing algorithm that acts as a pseudorandom function to generate derive keys.
            type: str
            choices:
              - hmac-sha1
              - hmac-sha224
              - hmac-sha256
              - hmac-sha384
              - hmac-sha512
              - hmac-sha512/224
              - hmac-sha512/256
              - hmac-sha3-224
              - hmac-sha3-256
              - hmac-sha3-384
              - hmac-sha3-512
            required: false
            default: null
          dklen:
            description: Intended length in octets of the derived key. dklen must be in range of 14 bytes to 512 bytes.
            type: int
            required: false
            default: null
          iteration:
            description:
              - Iteration count increase the cost of producing keys from a password
              - Iteration must be in range of 1 to 1,00,00,000.
            type: int
            required: false
            default: null
          password:
            description:
              - Base password to generate derive keys
              - It cannot be used in conjunction with passwordidentifier
              - password must be in range of 8 bytes to 128 bytes.
            type: str
            required: false
            default: null
          password_identifier:
            aliases: [passwordIdentifier]
            description: Secret password identifier for password. It cannot be used in conjunction with password.
            type: str
            required: false
            default: null
          password_identifier_type:
            aliases: [passwordIdentifierType]
            description: Type of the Passwordidentifier. If not set then default value is name.
            type: str
            choices: [id, name, slug]
            required: false
            default: null
          purpose:
            description:
              - User defined purpose
              - If specified will be prefixed to pbeSalt
              - pbePurpose must not be greater than 128 bytes.
            type: str
            required: false
            default: null
          salt:
            description: A Hex encoded string. pbeSalt must be in range of 16 bytes to 512 bytes.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrap_public_key:
        aliases: [wrapPublicKey]
        description:
          - If the algorithm is aes, tdes, hmac-*, seed or aria, this value will be used to encrypt the returned key material.
          - This value is ignored for other algorithms
          - Value must be an RSA public key, PEM-encoded public key in either PKCS1 or PKCS8 format, or a PEM-encoded X.509 certificate.
          - If set, the returned material value will be a Base64 encoded PKCS#1 v1.5 encrypted key.
          - View "wrapPublicKey" in export parameters for more information
          - Only applicable if includeMaterial is true.
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrap_public_key_padding:
        aliases: [wrapPublicKeyPadding]
        description:
          - WrapPublicKeyPadding specifies the type of padding scheme that needs to be set when importing the Key using the specified wrapkey
          - Accepted values are "pkcs1", "oaep", "oaep256", "oaep384", "oaep512"
          - and will default to "pkcs1" when wrapPublicKeyPadding is not set and WrapPublicKey is set.
          - While creating a new key, wrapPublicKeyPadding parameter should be specified only if includeMaterial is true
          - In this case, key will get created and in response wrapped material using specified wrapPublicKeyPadding and other wrap parameters will be returned.
          - Only applicable for op_type "export"
        type: str
        choices: [pkcs1, oaep, oaep256, oaep384, oaep512]
        required: false
        default: null
    wrap_rsaaes:
        aliases: [wrapRSAAES]
        description:
          - Information which is used to wrap/unwrap asymmetric keys using RSA AES KWP method
          - This method internally requires AES key size to generate a temporary AES key and RSA padding
          - To use WrapRSAAES, algorithm "RSA/RSAAESKEYWRAPPADDING" must be specified in WrappingEncryptionAlgo.
          - Only applicable for op_type "export"
        type: dict
        suboptions:
          aes_key_size:
            aliases: [aesKeySize]
            description: Size of AES key for RSA AES KWP
            type: int
            choices: [128, 192, 256]
            required: false
            default: 256
          padding:
            description: Padding specifies the type of padding scheme that needs to be set when exporting the Key using RSA AES wrap
            type: str
            choices: [oaep, oaep256, oaep384, oaep512]
            required: false
            default: oaep256
        required: false
        default: null
    wrapping_encryption_algo:
        aliases: [wrappingEncryptionAlgo]
        description:
          - It indicates the Encryption Algorithm information for wrapping the key. Format is Algorithm/Mode/Padding
          - Only applicable for op_type "export"
        type: str
        choices: [AES/AESKEYWRAP, AES/AESKEYWRAPPADDING, RSA/RSAAESKEYWRAPPADDING]
        required: false
        default: null
    wrapping_hash_algo:
        aliases: [wrappingHashAlgo]
        description:
          - This parameter specifies the hashing algorithm used if "wrappingMethod" corresponds to "mac/sign"
          - In case of MAC operation, the hashing algorithm used will be inferred from the type of HMAC key("macSignKeyIdentifier").
          - In case of SIGN operation, the possible values are sha1, sha224, sha256, sha384 or sha512
          - Only applicable for op_type "export"
        type: str
        required: false
        default: null
    wrapping_method:
        aliases: [wrappingMethod]
        description:
          - This parameter specifies the wrapping method used to wrap/mac/sign the key material.
          - Only applicable for op_type "export"
        type: str
        choices: [encrypt, mac/sign, pbe]
        required: false
        default: null
    new_key_name:
        aliases: [newKeyName]
        description:
          - Key name for the new cloned key.
          - Only applicable for op_type "clone"
        type: str
        required: false
        default: null
    meta:
        description:
          - Optional end-user or service data stored with the key
          - Only applicable for op_type "clone"
        type: dict
        required: false
        default: null
    id_size:
        aliases: [idSize]
        description:
          - Size of the ID for the key
          - Only applicable for op_type "clone"
        type: int
        required: false
        default: null
"""

EXAMPLES = """
- name: "Create Key"
  thalesgroup.ciphertrust.vault_keys2_op:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: create
    name: "key_name"
    algorithm: aes
    size: 256
    usageMask: 3145740
"""

RETURN = r"""
changed:
    description: Always C(true) when the action is performed; C(false) in check mode.
    returned: always
    type: bool
    sample: true
response:
    description: Raw response payload from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2 import (
    destroy,
    archive,
    recover,
    revoke,
    reactivate,
    export,
    clone,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

_wrap_HKDF = dict(
    hashAlgorithm=dict(
        type="str",
        choices=[
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ],
        required=False,
    ),
    info=dict(type="str", required=False),
    okmLen=dict(type="int", required=False),
    salt=dict(type="str", required=False),
)
_wrap_JWE = dict(
    contentEncryptionAlgorithm=dict(
        type="str",
        choices=[
            "AES_128_CBC_HMAC_SHA_256",
            "AES_192_CBC_HMAC_SHA_384",
            "AES_256_CBC_HMAC_SHA_512",
            "AES_128_GCM",
            "AES_192_GCM",
            "AES_256_GCM",
        ],
        default="AES_256_GCM",
        required=False,
    ),
    jwtIdentifier=dict(type="str", required=False),
    keyEncryptionAlgorithm=dict(
        type="str",
        choices=[
            "RSA1_5",
            "RSA_OAEP_SHA1",
            "RSA_OAEP_SHA256",
            "ECDH_ES",
            "ECDH_ES_AES_128_KEY_WRAP",
            "ECDH_ES_AES_192_KEY_WRAP",
            "ECDH_ES_AES_256_KEY_WRAP",
        ],
        default="RSA_OAEP_SHA1",
        required=False,
    ),
    keyIdentifier=dict(type="str", required=False, no_log=False),
)
_wrap_PBE = dict(
    dklen=dict(type="int", required=False),
    hashAlgorithm=dict(
        type="str",
        choices=[
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "hmac-sha512/224",
            "hmac-sha512/256",
            "hmac-sha3-224",
            "hmac-sha3-256",
            "hmac-sha3-384",
            "hmac-sha3-512",
        ],
        required=False,
    ),
    iteration=dict(type="int", required=False),
    password=dict(type="str", required=False, no_log=True),
    passwordIdentifier=dict(type="str", required=False, no_log=True),
    passwordIdentifierType=dict(
        type="str", choices=["name", "id", "slug"], required=False
    ),
    purpose=dict(type="str", required=False),
    salt=dict(type="str", required=False),
)
_wrap_RSAAES = dict(
    aesKeySize=dict(type="int", choices=[128, 192, 256], default=256, required=False),
    padding=dict(
        type="str",
        choices=["oaep", "oaep256", "oaep384", "oaep512"],
        default="oaep256",
        required=False,
    ),
)
_schema_less = dict()

argument_spec = dict(
    key_version=dict(type="int", required=False, no_log=False),
    id_type=dict(type="str", choices=["name", "id", "uri", "alias"], required=False),
    includeMaterial=dict(type="bool", default=False, required=False),
    op_type=dict(
        type="str",
        choices=[
            "destroy",
            "archive",
            "recover",
            "revoke",
            "reactivate",
            "export",
            "clone",
        ],
        required=True,
    ),
    cm_key_id=dict(type="str", required=True),
    reason=dict(
        type="str",
        choices=[
            "Unspecified",
            "KeyCompromise",
            "CACompromise",
            "AffiliationChanged",
            "Superseded",
            "CessationOfOperation",
            "PrivilegeWithdrawn",
            "DeactivatedToActive",
            "ActiveProtectStopToActive",
            "DeactivatedToActiveProtectStop",
        ],
    ),
    compromiseOccurrenceDate=dict(type="str", required=False),
    messageStr=dict(type="str", required=False),
    combineXts=dict(type="bool", required=False, default=False),
    encoding=dict(type="str", required=False),
    keyFormat=dict(
        type="str", choices=["pkcs1", "pkcs8", "pkcs12", "jwe"], required=False, no_log=False
    ),
    macSignKeyIdentifier=dict(type="str", required=False, no_log=False),
    macSignKeyIdentifierType=dict(
        type="str", choices=["name", "id", "alias"], required=False
    ),
    padded=dict(type="bool", required=False, default=False),
    password=dict(type="str", required=False, no_log=True),
    pemWrap=dict(type="bool", required=False, default=False),
    secretDataEncoding=dict(type="str", required=False, no_log=False),
    secretDataLink=dict(type="str", required=False, no_log=False),
    signingAlgo=dict(type="str", choices=["RSA", "RSA-PSS"], required=False),
    wrapHKDF=dict(type="dict", options=_wrap_HKDF, required=False),
    wrapJWE=dict(type="dict", options=_wrap_JWE, required=False),
    wrapKeyIDType=dict(type="str", choices=["name", "id", "alias"], required=False),
    wrapKeyName=dict(type="str", required=False, no_log=False),
    wrapPBE=dict(type="dict", options=_wrap_PBE, required=False),
    wrapPublicKey=dict(type="str", required=False, no_log=False),
    wrapPublicKeyPadding=dict(
        type="str",
        choices=["pkcs1", "oaep", "oaep256", "oaep384", "oaep512"],
        required=False,
    ),
    wrapRSAAES=dict(type="dict", options=_wrap_RSAAES, required=False),
    wrappingEncryptionAlgo=dict(
        type="str",
        choices=["AES/AESKEYWRAP", "AES/AESKEYWRAPPADDING", "RSA/RSAAESKEYWRAPPADDING"],
        required=False,
    ),
    wrappingHashAlgo=dict(type="str", required=False),
    wrappingMethod=dict(
        type="str", choices=["encrypt", "mac/sign", "pbe"], required=False
    ),
    newKeyName=dict(type="str", required=False, no_log=False),
    meta=dict(type="dict", options=_schema_less, required=False),
    idSize=dict(type="int", required=False),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "revoke", ["reason"]],
            ["op_type", "reactivate", ["reason"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "destroy":
            check_mode_action(module)
            response = destroy(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "archive":
            check_mode_action(module)
            response = archive(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "recover":
            check_mode_action(module)
            response = recover(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "revoke":
            check_mode_action(module)
            response = revoke(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
                reason=module.params.get("reason"),
                compromiseOccurrenceDate=module.params.get("compromiseOccurrenceDate"),
                messageStr=module.params.get("messageStr"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "reactivate":
            check_mode_action(module)
            response = reactivate(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
                reason=module.params.get("reason"),
                messageStr=module.params.get("messageStr"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "export":
            check_mode_action(module)
            response = export(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
                combineXts=module.params.get("combineXts"),
                encoding=module.params.get("encoding"),
                keyFormat=module.params.get("keyFormat"),
                macSignKeyIdentifier=module.params.get("macSignKeyIdentifier"),
                macSignKeyIdentifierType=module.params.get("macSignKeyIdentifierType"),
                padded=module.params.get("padded"),
                password=module.params.get("password"),
                pemWrap=module.params.get("pemWrap"),
                secretDataEncoding=module.params.get("secretDataEncoding"),
                secretDataLink=module.params.get("secretDataLink"),
                signingAlgo=module.params.get("signingAlgo"),
                wrapHKDF=module.params.get("wrapHKDF"),
                wrapJWE=module.params.get("wrapJWE"),
                wrapKeyIDType=module.params.get("wrapKeyIDType"),
                wrapKeyName=module.params.get("wrapKeyName"),
                wrapPBE=module.params.get("wrapPBE"),
                wrapPublicKey=module.params.get("wrapPublicKey"),
                wrapPublicKeyPadding=module.params.get("wrapPublicKeyPadding"),
                wrapRSAAES=module.params.get("wrapRSAAES"),
                wrapSymmetricKeyName=module.params.get("wrapSymmetricKeyName"),
                wrappingEncryptionAlgo=module.params.get("wrappingEncryptionAlgo"),
                wrappingHashAlgo=module.params.get("wrappingHashAlgo"),
                wrappingMethod=module.params.get("wrappingMethod"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "clone":
            check_mode_action(module)
            response = clone(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                key_version=module.params.get("key_version"),
                id_type=module.params.get("id_type"),
                includeMaterial=module.params.get("includeMaterial"),
                idSize=module.params.get("idSize"),
                meta=module.params.get("meta"),
                newKeyName=module.params.get("newKeyName"),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
