# SNMP v3 Agent framework

This is vy preliminary work towards a framework for developing SNMP v3 agents,           using the rasn ASN-1 library for decoding the on the wire data. While a manager (effectively a client) has to support a range of legacy agents, an agent (e.g. server) can offer a subset of features and still be useful.

The standards define the use of horrible old crypto types like single DES for privacy, and MD5 in the authentication. The code currently supports HMAC-SHA-1-96 and AES-128; stronger hashes and ciphers are planned for the future.

