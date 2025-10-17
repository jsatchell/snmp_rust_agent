# Issues to MVP

* Correct error response for simplest cases - Made a start. Missing below
  * Decode Error
  * Permission Errors (in some cases), most now correct
  * Wrong encoding / size
* Tests - Started. OK coverage of agent, started compiler, nothing for generated code.
  * Table - 8
  * Oidmap - 1
  * Perms - 3
  * Scalar - 10
  * Usm - 12
  * Utils - 8
  * Config - 2
  * Privacy - 2, check round trip, no test cases in RFCs.
  * Agent -  8 Hardest, needs mocks etc.
  * Engine ID - 9
  * stub-gen/resolver - 3
  * stub-gen/parser - 8
  * stub-gen/gen_stub - 10  Needs tempfile for the rest
  * keeper - 8
* Table model
  * Text-Convention and sub type range checking (lookup done for DEFVAL) - TODO
  * Default Values - mostly done
  * Augment tables - FIXME - wrong implementation, needs Rust support to do right, do after MVP
  * Row management via row status column
    * Delete - Done
    * Active / "not in service" switching - Done
    * Create and Wait - Done
    * Create and Go - After MVP
  * Extra errors - done except for permissions / read-only
* Transaction model for SET - nearly done
  * Change to OidKeep Trait - begin_transaction, commit, rollback - Done
  * commitfail, undofail errors - ToDo
  * sample implementations for ScalarMemOid and TableMemOid - Done
  * Compiler support - Done
  * snmp_agent use new API - Done
* Outline of MiB compiler / code generator - Started, rust one replaces python prototype.
* Improved permissions model - Done
* Get-bulk - Done, but error handling is hope and wishful thinking
* At least two MIB fairly complete implementations that are not just stubs:
  * SNMPv2  - started, mostly done
  * SNMP-USER-BASED-SM - started, no password change or user creation from templates yet.


## After MVP

* no panics in run time loop
* more hash / cipher choices (at least SHA-256, maybe AES-256, but no standard for that) - RFC 7630
* View model and user mapping to views
* Multiple contexts - separate Oid maps?
* Traps / Informs
* Augments / foreign indices support in compiler and Rust code
