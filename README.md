# SNMP v3 Agent framework

This is very preliminary work towards a framework for developing SNMP v3 agents, using the rasn ASN-1 library for decoding the on the wire data. While a manager (effectively a client) has to support a range of legacy agents, an agent (e.g. server) can offer a subset of features and still be useful.

The standards define the use of horrible old crypto types like single DES for privacy, and MD5 in the authentication. The code currently supports HMAC-SHA-1-96 and AES-128; stronger hashes and ciphersfrom RFC7360 are planned for the future. It is not clear that using stronger hash functions or ciphers will deliver significant advantages in practice. The well known collision weakness of SHA-1 is not a problem in an HMAC application.

The agent server loop is a single threaded blocking design. I would argue that this is appropriate for almost all agents, as typically a single manager will interact with multiple agents. Managers may well want to support high levels of concurrency. The single threaded design avoids many issues with concurrency and locking. Of course, there is nothing to stop handlers for specific long running operations using a thread, and this might be a good option for the CreateAndWait model of table row creation. Good luck with that!

At present, there is no permissions model at all, and most real world applications will need that. Coming real soon. It may not be RFC view action model, as that seems complex, and the facility to dynamically change the permissions model remotely is not often implemented. Instead, some sort of compile time model seems more appropriate to the sort of boxes that run agents.

At present, there is only very rough tooling to help implement an useful agent, but it is just about possible with enough patience. The ugliest bit of python I have ever written is in tools/mib-play.py. For some MIBs, it can generate Rust code that might compile. If you want it to do something useful, you need to write your own back-end implementation. The basic idea is to associate instances that support the OidKeeper trait with the OID value or values that they support in the OidMap. This is populated and then the agent loop_forever() runs.

Two toy implementations of the OidKeeper trait are provided by way of example, both purely memory based. One is for scalars, and the other is a very limited table model with a fixed number of rows. Set can change cell values in existing rows. If you change the value of index cells, the results may be puzzling.

As you add further struct implementations to do useful things, you will need to add them to the OT enum in main.rs. At a minimum, for scalars, you need to implement get and set.
