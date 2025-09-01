# Issues to MVP

* Correct error response for simplest cases - Made a start. Missing below
  * Decode Error
  * Authentication Error
  * Permission Errors (in some cases)
  * Wrong encoding / size
* Tests - Started
  * Table - 6
  * Scalar - 4
  * Usm - 6
  * Config - 1
  * Privacy - no test cases in RFCs.
  * Agent -  4 Hardest, needs mocks etc.
  * Engine ID - 4
* Table model
  * Text-Convention range checking (lookup done for DEFVAL)
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
  * Compiler support - Done for Rust
  * snmp_agent use new API - Done
* Rough outline of MiB compiler / code generator - Started, both python and rust.
* Simplistic permissions model - Done, maybe too simple!
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
