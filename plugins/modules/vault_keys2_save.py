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

DOCUMENTATION = """
---
module: vault_keys2_save
short_description: Create or update keys in CipherTrust Manager managed vault
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs
    - For keys management API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
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
        auth_domain_path:
          description: user''s domain path
          type: str
          required: true
    op_type:
        description: Operation to be performed
        choices: [create, patch, create_version]
        required: true
        type: str
    cm_key_id:
        description:
          - CM ID of the key that needs to be patched.
          - Only required if the op_type is patch or create_version
        type: str
        default: null
    activationDate:
        description: Date/time the object becomes active
        required: false
        type: str
        default: null
    algorithm:
        description:
          - Cryptographic algorithm this key is used with.
          - Defaults to aes
        type: str
        required: false
        choices: [aes, tdes, rsa, ec, hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512, seed, aria, opaque]
        default: aes
    password:
        description:
          - For pkcs12 format, either password or secretDataLink should be specified
          - This should be the base64 encoded value of the password.
        type: str
    aliases:
        description:
          - Aliases associated with the key.
          - The alias and alias-type must be specified.
          - The alias index is assigned by this operation, and need not be specified.
        type: list
        elements: dict
        suboptions:
          alias:
            description: An alias for a key name
            type: str
          index:
            description: Index associated with alias. Each alias within an object has a unique index
            type: int
          type:
            description: Type of alias (allowed values are string and uri)
            type: str
        required: false
    archiveDate:
        description: Date/time the object becomes archived
        required: false
        default: null
        type: str
    certType:
        description:
          - This specifies the type of certificate object that is being created
          - Valid values are x509-pem and x509-der
          - At present, we only support x.509 certificates
          - The cerfificate data is passed in via the material field
          - The certificate type is infered from the material if it is left blank.
        type: str
        choices: [x509-pem, x509-der]
        required: false
        default: null
    compromiseDate:
        description: Date/time the object entered into the compromised state.
        type: str
        required: false
        default: null
    compromiseOccurrenceDate:
        description:
          - Date/time when the object was first believed to be compromised, if known
          - Only valid if the revocation reason is CACompromise or KeyCompromise, otherwise ignored.
        type: str
        required: false
        default: null
    curveid:
        description:
          - Cryptographic curve id for elliptic key.
          - Key algorithm must be EC
        choices:
          - secp224k1
          - secp224r1
          - secp256k1
          - secp384r1
          - secp521r1
          - prime256v1
          - brainpoolP224r1
          - brainpoolP224t1
          - brainpoolP256r1
          - brainpoolP256t1
          - brainpoolP384r1
          - brainpoolP384t1
          - brainpoolP512r1
          - brainpoolP512t1
        type: str
        required: false
        default: null
    deactivationDate:
        description: Date/time the object becomes inactive
        type: str
        required: false
        default: null
    defaultIV:
        description: Deprecated
        type: str
        required: false
        default: null
    destroyDate:
        description: Date/time the object was destroyed.
        type: str
        required: false
        default: null
    encoding:
        description:
          - Specifies the encoding used for the material field.
        type: str
        required: false
        default: null
    format:
        description:
          - This parameter is used while importing keys (material is not empty)
          - For Asymmetric keys, When this parameter is not specified
          - For Symmetric keys, When importing keys if specified, the value must be given according to the format of the material.
          - Options are raw or opaque
        type: str
        required: false
        default: null
    generateKeyId:
        description: If specified as true, the key''s keyId identifier of type long is generated. Defaults to false.
        type: bool
        required: false
        default: false
    hkdfCreateParameters:
        description: Information which is used to create a Key using HKDF.
        type: dict
        suboptions:
          hashAlgorithm:
            description:
              - Hash Algorithm is used for HKDF.
              - This is required if ikmKeyName is specified, default is hmac-sha256.
            type: str
            choices: [hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512]
            default: hmac-sha256
          ikmKeyName:
            description: Any existing symmetric key. Mandatory while using HKDF key generation.
            type: str
            required: false
          info:
            description: Info is an optional hex value for HKDF based derivation.
            type: str
            required: false
          salt:
            description: Salt is an optional hex value for HKDF based derivation.
            type: str
            required: false
        required: false
        default: null
    id:
        description:
          - This optional parameter specifies the identifier of the key (id)
          - It is used only when creating keys with specific key material. If set, the key''s id is set to this value.
        type: str
        required: false
        default: null
    idSize:
        description: Size of the ID for the key
        type: int
        required: false
        default: null
    keyId:
        description:
          - Additional identifier of the key. The format of this value is of type long
          - This is optional and applicable for import key only. If set, the value is imported as the key''s keyId.
        type: str
        required: false
        default: null
    labels:
        description:
          - Optional key/value pairs used to group keys
        type: dict
        required: false
        default: null
    macSignBytes:
        description:
          - This parameter specifies the MAC/Signature bytes to be used for verification while importing a key
          - The "wrappingMethod" should be "mac/sign" and the required parameters for the verification must be set.
        type: str
        required: false
        default: null
    macSignKeyIdentifier:
        description:
          - This parameter specifies the identifier of the key to be used for generating MAC or signature of the key material
          - The "wrappingMethod" should be "mac/sign" to verify the MAC/signature("macSignBytes") of the key material("material")
          - For verifying the MAC, the key has to be a HMAC key
          - For verifying the signature, the key has to be an RSA private or public key.
        type: str
        required: false
        default: null
    macSignKeyIdentifierType:
        description:
          - This parameter specifies the identifier of the key("macSignKeyIdentifier") used for generating MAC or signature of the key material
          - The "wrappingMethod" should be "mac/sign" to verify the mac/signature("macSignBytes") of the key material("material")
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    material:
        description:
          - If set, the value will be imported as the key''s material
          - If not set, new key material will be generated on the server
        type: str
        required: false
        default: null
    meta:
        description: Optional end-user or service data stored with the key
        type: dict
        suboptions:
          ownerId:
            description:
              - Optional owner information for the key, required for non-admin. Value should be the user''s user_id
            type: str
            required: false
            default: null
          permissions:
            description:
              - Optional permissions associated with this key
            type: dict
            suboptions:
              UseKey:
                description: Permission to use key
                type: list
                elements: str
              ReadKey:
                description: Permission to read key
                type: list
                elements: str
              ExportKey:
                description: Permission to export key
                type: list
                elements: str
              MACWithKey:
                description: Permission to use MAC with key
                type: list
                elements: str
              SignWithKey:
                description: Permission to sign with the key
                type: list
                elements: str
              DecryptWithKey:
                description: Permission to descrypt with the key
                type: list
                elements: str
              EncryptWithKey:
                description: Permission to encrypt with the key
                type: list
                elements: str
              MACVerifyWithKey:
                description: Permission to verify MAC with the key
                type: list
                elements: str
              SignVerifyWithKey:
                description: Permission to verify sign with the key
                type: list
                elements: str
          cte:
            description:
              - CTE specific permissions
            type: dict
            suboptions:
              persistent_on_client:
                description: Allow persisting key on the client
                type: bool
              encryption_mode:
                description: Specify encryption mode
                type: str
              cte_versioned:
                description: CTE versioned
                type: bool
          versionedKey:
            description: if the key is versioned
            type: bool
        required: false
        default: null
    muid:
        description:
          - Additional identifier of the key
          - This is optional and applicable for import key only
          - If set, the value is imported as the key''s muid.
        type: str
        required: false
        default: null
    name:
        description:
          - Optional friendly name
          - The key name should not contain special characters such as angular brackets (<,>) and backslash ().
        type: str
        required: false
        default: null
    objectType:
        description:
          - This specifies the type of object that is being created
          - The object type is inferred for many objects, but must be supplied for the certificate object.
        type: str
        choices: [Symmetric Key, Public Key, Private Key, Secret Data, Opaque Object, Certificate]
        required: false
        default: null
    padded:
        description:
          - This parameter determines the padding for the wrap algorithm while unwrapping a symmetric key
        type: bool
        required: false
        default: false
    processStartDate:
        description:
          - Date/time when a Managed Symmetric Key Object MAY begin to be used to process cryptographically protected information
        type: str
        required: false
        default: null
    protectStopDate:
        description:
          - Date/time after which a Managed Symmetric Key Object SHALL NOT be used for applying cryptographic protection
        type: str
        required: false
        default: null
    publicKeyParameters:
        description: Information needed to create a public key
        type: dict
        suboptions:
          activationDate:
            description: Date/time the object becomes active
            required: false
            type: str
            default: null
          aliases:
            description:
              - Aliases associated with the key.
              - The alias and alias-type must be specified.
              - The alias index is assigned by this operation, and need not be specified.
            type: list
            elements: dict
            suboptions:
              alias:
                description: alias
                type: str
              index:
                description: alias index
                type: int
              type:
                description: alias type
                type: str
            required: false
          archiveDate:
            description: Date/time the object becomes archived
            required: false
            default: null
            type: str
          deactivationDate:
            description: Date/time the object becomes inactive
            type: str
            required: false
            default: null
          meta:
            description: Optional end-user or service data stored with the key
            type: dict
            required: false
            default: null
          name:
            description: Optional friendly name
            type: str
            required: false
            default: null
          state:
            description:
              - Optional initial key state (Pre-Active) upon creation
              - Defaults to Active
            type: str
            required: false
            default: null
          undeletable:
            description: Key is not deletable. Defaults to false.
            type: bool
            required: false
            default: false
          unexportable:
            description: Key is not exportable. Defaults to false.
            type: bool
            required: false
            default: false
          usageMask:
            description:
                - Cryptographic usage mask.
                - Add the usage masks to allow certain usages.
                - Sign (1)
                - Verify (2)
                - Encrypt (4)
                - Decrypt (8)
                - Wrap Key (16)
                - Unwrap Key (32)
                - Export (64)
                - MAC Generate (128)
                - MAC Verify (256)
                - Derive Key (512)
                - Content Commitment (1024)
                - Key Agreement (2048)
                - Certificate Sign (4096)
                - CRL Sign (8192)
                - Generate Cryptogram (16384)
                - Validate Cryptogram (32768)
                - Translate Encrypt (65536)
                - Translate Decrypt (131072)
                - Translate Wrap (262144)
                - Translate Unwrap (524288)
                - FPE Encrypt (1048576)
                - FPE Decrypt (2097152)
                - Add the usage mask values to allow the usages
            type: int
            default: null
            required: false
        required: false
        default: null
    revocationMessage:
        description: Message explaining revocation.
        type: str
        required: false
        default: null
    revocationReason:
        description: The reason the key is being revoked.
        choices: [Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation, PrivilegeWithdrawn]
        type: str
        required: false
        default: null
    rotationFrequencyDays:
        description:
            - Number of days from current date to rotate the key.
            - It should be greater than or equal to 0.
            - Default is an empty string.
            - If set to 0, rotationFrequencyDays set to an empty string and auto rotation of key will be disabled.
        type: str
        required: false
        default: null
    secretDataEncoding:
        description:
            - For pkcs12 format, this field specifies the encoding method used for the secretDataLink material.
            - Ignore this field if secretData is created from REST and is in plain format.
            - Specify the value of this field as HEX format if secretData is created from KMIP.
        type: str
        required: false
        default: null
    secretDataLink:
        description:
            - For pkcs12 format, either secretDataLink or password should be specified.
            - The value can be either ID or name of Secret Data.
        type: str
        required: false
        default: null
    signingAlgo:
        description:
            - This parameter specifies the algorithm to be used for generating the signature
            - Signature for the verification of the "macSignBytes" during import of key material.
            - The "wrappingMethod" should be "mac/sign" to verify the signature("macSignBytes") of the key material("material").
        choices: [RSA, RSA-PSS]
        type: str
        required: false
        default: null
    size:
        description: Bit length for the key.
        type: int
        required: false
        default: null
    state:
        description:
          - Optional initial key state (Pre-Active) upon creation. Defaults to Active.
        type: str
        required: false
        default: null
    undeletable:
        description: Key is not deletable. Defaults to false.
        type: bool
        required: false
        default: false
    unexportable:
        description: Key is not exportable. Defaults to false.
        type: bool
        required: false
        default: false
    usageMask:
        description:
          - Cryptographic usage mask
          - Add the usage masks to allow certain usages
          - Sign (1)
          - Verify (2)
          - Encrypt (4)
          - Decrypt (8)
          - Wrap Key (16)
          - Unwrap Key (32)
          - Export (64)
          - MAC Generate (128)
          - MAC Verify (256)
          - Derive Key (512)
          - Content Commitment (1024)
          - Key Agreement (2048)
          - Certificate Sign (4096)
          - CRL Sign (8192)
          - Generate Cryptogram (16384)
          - Validate Cryptogram (32768)
          - Translate Encrypt (65536)
          - Translate Decrypt (131072)
          - Translate Wrap (262144)
          - Translate Unwrap (524288)
          - FPE Encrypt (1048576)
          - FPE Decrypt (2097152)
          - Add the usage mask values to allow the usages
          - To set all usage mask bits, use 4194303
          - Equivalent usageMask values for deprecated usages fpe (FPE Encrypt + FPE Decrypt = 3145728)
          - blob (Encrypt + Decrypt = 12)
          - hmac (MAC Generate + MAC Verify = 384)
          - encrypt (Encrypt + Decrypt = 12)
          - sign (Sign + Verify = 3)
          - any (4194303 - all usage masks).
        type: int
        default: null
        required: false
    uuid:
        description:
          -Additional identifier of the key
        type: str
        required: false
        default: null
    wrapHKDF:
        description: Information which is used to wrap a Key using HKDF.
        type: dict
        suboptions:
          hashAlgorithm:
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
          okmLen:
            description: The desired output key material length in integer.
            type: int
            required: false
          salt:
            description: Salt is an optional hex value for HKDF based derivation.
            type: str
            required: false
            default: null
        required: false
        default: null
    wrapKeyIDType:
        description: IDType specifies how the wrapKeyName should be interpreted.
        type: str
        choices: [name, id, alias]
        required: false
        default: null
    wrapKeyName:
        description:
          - While creating a new key, If includeMaterial is true, then only the key material will be wrapped with key material.
          - The response "material" property will be the base64 encoded ciphertext
          - While importing a key, the key material will be unwrapped with material of the specified key name
          - The only applicable "wrappingMethod" for the unwrapping is "encrypt"
          - and the wrapping key has to be an AES key or an RSA private key.
        type: str
        required: false
        default: null
    wrapPBE:
        description:
          - WrapPBE produces a derived key from a password and other parameters like salt
          - PBE is currently only supported to wrap symmetric keys (AES), private Keys and certificates.
        type: dict
        suboptions:
          hashAlgorithm:
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
              - Password must be in range of 8 bytes to 128 bytes.
            type: str
            required: false
            default: null
          passwordIdentifier:
            description:
              - Secret password identifier for password
              - It cannot be used in conjunction with password.
            type: str
            required: false
            default: null
          passwordIdentifierType:
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
    wrapPublicKey:
        description:
          - If the algorithm is aes, tdes, hmac-*, seed or aria, this value will be used to encrypt the returned key material
          - This value is ignored for other algorithms
        type: str
        required: false
        default: null
    wrapPublicKeyPadding:
        description:
          - WrapPublicKeyPadding specifies the type of padding scheme that needs to be set when importing the Key using the specified wrapkey
          - Accepted values are "pkcs1", "oaep", "oaep256", "oaep384", "oaep512"
          - Will default to "pkcs1" when wrapPublicKeyPadding is not set and WrapPublicKey is set.
          - While creating a new key, wrapPublicKeyPadding parameter should be specified only if includeMaterial is true
          - In this case, key will get created and in response wrapped material using specified wrapPublicKeyPadding and other wrap parameters will be returned.
        type: str
        choices: [pkcs1, oaep, oaep256, oaep384, oaep512]
        required: false
        default: null
    wrapRSAAES:
        description:
          - Information which is used to wrap/unwrap asymmetric keys using RSA AES KWP method
          - This method internally requires AES key size to generate a temporary AES key and RSA padding
          - To use WrapRSAAES, algorithm "RSA/RSAAESKEYWRAPPADDING" must be specified in WrappingEncryptionAlgo.
        type: dict
        suboptions:
          aesKeySize:
            description: Size of AES key for RSA AES KWP.
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
    wrappingEncryptionAlgo:
        description:
          - It indicates the Encryption Algorithm information for wrapping the key. Format is Algorithm/Mode/Padding
        type: str
        choices: [AES/AESKEYWRAP, AES/AESKEYWRAPPADDING, RSA/RSAAESKEYWRAPPADDING]
        required: false
        default: null
    wrappingHashAlgo:
        description:
          - This parameter specifies the hashing algorithm used if "wrappingMethod" corresponds to "mac/sign"
          - In case of MAC operation, the hashing algorithm used will be inferred from the type of HMAC key("macSignKeyIdentifier").
          - In case of SIGN operation, the possible values are sha1, sha224, sha256, sha384 or sha512
        type: str
        required: false
        default: null
    wrappingMethod:
        description:
          - This parameter specifies the wrapping method used to wrap/mac/sign the key material.
        type: str
        choices: [encrypt, mac/sign, pbe]
        required: false
        default: null
    xts:
        description: If set to true, then key created will be XTS/CBC-CS1 Key. Defaults to false. Key algorithm must be AES.
        type: bool
        required: false
        default: false
    allVersions:
        description:
          - To update the group permissions/custom attribute or both in metadata of all versions of the key
          - By default it is set to false
          - Set to true, only when to update the group/custom attribute or both permissions of all versions of the key.
          - Only applicable for op_type patch
        type: bool
        required: false
        default: false
    offset:
        description:
          - An Offset MAY be used to indicate the difference between the Creation Date and the Activation Date of the replacement key.
          - Only applicable for op_type create_version
        type: int
        required: false

"""

EXAMPLES = """
- name: "Create Key"
  thalesgroup.ciphertrust.vault_keys2_create:
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

- name: "Patch Key"
  thalesgroup.ciphertrust.vault_keys2_create:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: patch
    cm_key_id: "4ae2649a705e479589ef65759d3287f6ff452a788531445fbc7f0240516d028d"
    unexportable: false
"""

RETURN = """
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2 import (
    create,
    patch,
    version_create,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_alias = dict(
    alias=dict(type="str"),
    index=dict(type="int"),
    type=dict(type="str"),
)
_cte = dict(
    persistent_on_client=dict(type="bool"),
    encryption_mode=dict(type="str"),
    cte_versioned=dict(type="bool"),
)
_permission = dict(
    UseKey=dict(type="list", elements="str"),
    ReadKey=dict(type="list", elements="str"),
    ExportKey=dict(type="list", elements="str"),
    MACWithKey=dict(type="list", elements="str"),
    SignWithKey=dict(type="list", elements="str"),
    DecryptWithKey=dict(type="list", elements="str"),
    EncryptWithKey=dict(type="list", elements="str"),
    MACVerifyWithKey=dict(type="list", elements="str"),
    SignVerifyWithKey=dict(type="list", elements="str"),
)
_meta = dict(
    ownerId=dict(type="str", required=False),
    permissions=dict(type="dict", options=_permission),
    cte=dict(type="dict", options=_cte),
    versionedKey=dict(type="bool"),
)
_schema_less = dict()
_hkdfParam = dict(
    hashAlgorithm=dict(
        type="str",
        choices=[
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ],
        default="hmac-sha256",
        required=False,
    ),
    ikmKeyName=dict(type="str", required=False),
    info=dict(type="str", required=False),
    salt=dict(type="str", required=False),
)
_public_key_param = dict(
    activationDate=dict(type="str", required=False),
    aliases=dict(type="list", elements="dict", options=_alias, required=False),
    archiveDate=dict(type="str", required=False),
    deactivationDate=dict(type="str", required=False),
    meta=dict(type="dict", options=_schema_less, required=False),
    name=dict(type="str", required=False),
    state=dict(type="str", required=False),
    undeletable=dict(type="bool", default=False, required=False),
    unexportable=dict(type="bool", default=False, required=False),
    usageMask=dict(type="int", required=False),
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
    password=dict(type="str", required=False),
    passwordIdentifier=dict(type="str", required=False),
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

argument_spec = dict(
    op_type=dict(
        type="str", choices=["create", "patch", "create_version"], required=True
    ),
    cm_key_id=dict(type="str"),
    activationDate=dict(type="str", required=False),
    algorithm=dict(
        type="str",
        required=False,
        choices=[
            "aes",
            "tdes",
            "rsa",
            "ec",
            "hmac-sha1",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "seed",
            "aria",
            "opaque",
        ],
        default="aes",
    ),
    aliases=dict(type="list", elements="dict", options=_alias, required=False),
    archiveDate=dict(type="str", required=False),
    certType=dict(type="str", choices=["x509-pem", "x509-der"], required=False),
    compromiseDate=dict(type="str", required=False),
    compromiseOccurrenceDate=dict(type="str", required=False),
    curveid=dict(
        type="str",
        choices=[
            "secp224k1",
            "secp224r1",
            "secp256k1",
            "secp384r1",
            "secp521r1",
            "prime256v1",
            "brainpoolP224r1",
            "brainpoolP224t1",
            "brainpoolP256r1",
            "brainpoolP256t1",
            "brainpoolP384r1",
            "brainpoolP384t1",
            "brainpoolP512r1",
            "brainpoolP512t1",
        ],
        required=False,
    ),
    deactivationDate=dict(type="str", required=False),
    defaultIV=dict(type="str", required=False),
    destroyDate=dict(type="str", required=False),
    encoding=dict(type="str", required=False),
    format=dict(type="str", required=False),
    generateKeyId=dict(type="bool", required=False, default=False),
    hkdfCreateParameters=dict(type="dict", options=_hkdfParam, required=False),
    id=dict(type="str", required=False),
    idSize=dict(type="int", required=False),
    keyId=dict(type="str", required=False),
    labels=dict(type="dict", options=_schema_less, required=False),
    macSignBytes=dict(type="str", required=False),
    macSignKeyIdentifier=dict(type="str", required=False),
    macSignKeyIdentifierType=dict(
        type="str", choices=["name", "id", "alias"], required=False
    ),
    material=dict(type="str", required=False),
    meta=dict(type="dict", options=_meta, required=False),
    muid=dict(type="str", required=False),
    name=dict(type="str", required=False),
    objectType=dict(
        type="str",
        choices=[
            "Symmetric Key",
            "Public Key",
            "Private Key",
            "Secret Data",
            "Opaque Object",
            "Certificate",
        ],
        required=False,
    ),
    padded=dict(type="bool", default=False, required=False),
    password=dict(type="str", required=False),
    processStartDate=dict(type="str", required=False),
    protectStopDate=dict(type="str", required=False),
    publicKeyParameters=dict(type="dict", options=_public_key_param, required=False),
    revocationMessage=dict(type="str", required=False),
    revocationReason=dict(
        type="str",
        choices=[
            "Unspecified",
            "KeyCompromise",
            "CACompromise",
            "AffiliationChanged",
            "Superseded",
            "CessationOfOperation",
            "PrivilegeWithdrawn",
        ],
        required=False,
    ),
    rotationFrequencyDays=dict(type="str", required=False),
    secretDataEncoding=dict(type="str", required=False),
    secretDataLink=dict(type="str", required=False),
    signingAlgo=dict(type="str", choices=["RSA-PSS", "RSA"], required=False),
    size=dict(type="int", required=False),
    state=dict(type="str", required=False),
    undeletable=dict(type="bool", required=False, default=False),
    unexportable=dict(type="bool", required=False, default=False),
    usageMask=dict(type="int", required=False),
    uuid=dict(type="str", required=False),
    wrapHKDF=dict(type="dict", options=_wrap_HKDF, required=False),
    wrapKeyIDType=dict(type="str", choices=["name", "id", "alias"], required=False),
    wrapKeyName=dict(type="str", required=False),
    wrapPBE=dict(type="dict", options=_wrap_PBE, required=False),
    wrapPublicKey=dict(type="str", required=False),
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
    xts=dict(type="bool", required=False, default=False),
    allVersions=dict(
        type="bool", required=False, default=False
    ),  # applicable to the patch operation only
    offset=dict(
        type="int", required=False
    ),  # applicable to the create_version operation only
)


def validate_parameters(user_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["cm_key_id"]],
            ["op_type", "create_version", ["cm_key_id"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = create(
                node=module.params.get("localNode"),
                activationDate=module.params.get("activationDate"),
                algorithm=module.params.get("algorithm"),
                aliases=module.params.get("aliases"),
                archiveDate=module.params.get("archiveDate"),
                certType=module.params.get("certType"),
                compromiseDate=module.params.get("compromiseDate"),
                compromiseOccurrenceDate=module.params.get("compromiseOccurrenceDate"),
                curveid=module.params.get("curveid"),
                deactivationDate=module.params.get("deactivationDate"),
                defaultIV=module.params.get("defaultIV"),
                destroyDate=module.params.get("destroyDate"),
                encoding=module.params.get("encoding"),
                format=module.params.get("format"),
                generateKeyId=module.params.get("generateKeyId"),
                hkdfCreateParameters=module.params.get("hkdfCreateParameters"),
                id=module.params.get("id"),
                idSize=module.params.get("idSize"),
                keyId=module.params.get("keyId"),
                labels=module.params.get("labels"),
                macSignBytes=module.params.get("macSignBytes"),
                macSignKeyIdentifier=module.params.get("macSignKeyIdentifier"),
                macSignKeyIdentifierType=module.params.get("macSignKeyIdentifierType"),
                material=module.params.get("material"),
                meta=module.params.get("meta"),
                muid=module.params.get("muid"),
                name=module.params.get("name"),
                objectType=module.params.get("objectType"),
                padded=module.params.get("padded"),
                password=module.params.get("password"),
                processStartDate=module.params.get("processStartDate"),
                protectStopDate=module.params.get("protectStopDate"),
                publicKeyParameters=module.params.get("publicKeyParameters"),
                revocationMessage=module.params.get("revocationMessage"),
                revocationReason=module.params.get("revocationReason"),
                rotationFrequencyDays=module.params.get("rotationFrequencyDays"),
                secretDataEncoding=module.params.get("secretDataEncoding"),
                secretDataLink=module.params.get("secretDataLink"),
                signingAlgo=module.params.get("signingAlgo"),
                size=module.params.get("size"),
                state=module.params.get("state"),
                undeletable=module.params.get("undeletable"),
                unexportable=module.params.get("unexportable"),
                usageMask=module.params.get("usageMask"),
                uuid=module.params.get("uuid"),
                wrapHKDF=module.params.get("wrapHKDF"),
                wrapKeyIDType=module.params.get("wrapKeyIDType"),
                wrapKeyName=module.params.get("wrapKeyName"),
                wrapPBE=module.params.get("wrapPBE"),
                wrapPublicKey=module.params.get("wrapPublicKey"),
                wrapPublicKeyPadding=module.params.get("wrapPublicKeyPadding"),
                wrapRSAAES=module.params.get("wrapRSAAES"),
                wrappingEncryptionAlgo=module.params.get("wrappingEncryptionAlgo"),
                wrappingHashAlgo=module.params.get("wrappingHashAlgo"),
                wrappingMethod=module.params.get("wrappingMethod"),
                xts=module.params.get("xts"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "patch":
        try:
            response = patch(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                activationDate=module.params.get("activationDate"),
                aliases=module.params.get("aliases"),
                allVersions=module.params.get("allVersions"),
                archiveDate=module.params.get("archiveDate"),
                compromiseOccurrenceDate=module.params.get("compromiseOccurrenceDate"),
                deactivationDate=module.params.get("deactivationDate"),
                keyId=module.params.get("keyId"),
                labels=module.params.get("labels"),
                meta=module.params.get("meta"),
                muid=module.params.get("muid"),
                processStartDate=module.params.get("processStartDate"),
                protectStopDate=module.params.get("protectStopDate"),
                revocationMessage=module.params.get("revocationMessage"),
                revocationReason=module.params.get("revocationReason"),
                rotationFrequencyDays=module.params.get("rotationFrequencyDays"),
                undeletable=module.params.get("undeletable"),
                unexportable=module.params.get("unexportable"),
                usageMask=module.params.get("usageMask"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    else:
        try:
            response = version_create(
                node=module.params.get("localNode"),
                cm_key_id=module.params.get("cm_key_id"),
                aliases=module.params.get("aliases"),
                certType=module.params.get("certType"),
                defaultIV=module.params.get("defaultIV"),
                encoding=module.params.get("encoding"),
                format=module.params.get("format"),
                idSize=module.params.get("idSize"),
                keyId=module.params.get("keyId"),
                labels=module.params.get("labels"),
                material=module.params.get("material"),
                muid=module.params.get("muid"),
                offset=module.params.get("offset"),
                padded=module.params.get("padded"),
                uuid=module.params.get("uuid"),
                wrapKeyIDType=module.params.get("wrapKeyIDType"),
                wrapKeyName=module.params.get("wrapKeyName"),
                wrapPublicKey=module.params.get("wrapPublicKey"),
                wrapPublicKeyPadding=module.params.get("wrapPublicKeyPadding"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
