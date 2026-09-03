# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)


def new(node, **fields):
    cm = node
    client = CipherTrustClient(cm)
    payload = json.dumps({
        "localNodeHost": cm["server_private_ip"],
        "localNodePort": cm["server_port"],
        "publicAddress": cm["server_ip"],
    })
    client.post("cluster/new", data=payload)
    return "Cluster creation initiated successfully!"


def csr(node, master, **fields):
    client = CipherTrustClient(node)
    payload = json.dumps({
        "localNodeHost": node["server_private_ip"],
        "publicAddress": master["server_ip"],
    })
    response = client.post("cluster/csr", data=payload)
    return response.get("csr", response)


def sign(node, master, csr, **fields):
    client = CipherTrustClient(master)
    payload = json.dumps({
        "csr": csr,
        "shared_hsm_partition": False,
        "newNodeHost": node["server_private_ip"],
        "publicAddress": master["server_ip"],
    })
    return client.post("nodes", data=payload)


def join(node, master, cert, caChain, mkek_blob, **fields):
    client = CipherTrustClient(node)
    payload = json.dumps({
        "cert": cert,
        "cachain": caChain,
        "localNodeHost": node["server_private_ip"],
        "localNodePort": 5432,
        "localNodePublicAddress": node["server_ip"],
        "memberNodeHost": master["server_private_ip"],
        "memberNodePort": 5432,
        "mkek_blob": mkek_blob,
        "blocking": False,
    })
    return client.post("cluster/join", data=payload)
