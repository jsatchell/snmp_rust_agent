# Issues to MVP

* Privacy - Done
* Swap to Vec for Oid table - Done
* Get-next - Done, maybe bugs
* Trait for OidKeeper, and sample Impls - Done
* Change OidMap type to OidKeeper - Done
* Set (for scalars only) - Done
* Correct error response for simplest cases - Made a start. Missing below
  * Decode Error
  * Authentication Error
  * Permission Errors (in some cases)
  * Wrong encoding / size
* Tests - Started
  * Table - 5
  * Scalar - 4
  * Usm - 4
  * Config - 1
  * Privacy - no test cases in RFCs.
  * Agent -  Hardest, needs mocks etc.
  * Engine ID - 3
* Debug /Fix Getnext so snmpwalk works - done?
* Table model
  * Integer indices in column 1 - Done
    * Get - Done
    * Set existing cells - Done
  * Multi-column indices: Integers, strings and addresses - done.
  * Text-Convention range checking (lookup done for DEFVAL)
  * Default Values - mostly done
  * Augment tables - FIXME - wrong implementation, needs Rust support to do right, do after MVP
  * Row management via row status column
    * Delete - Done
    * Active / "not in service" switching - Done
    * Create and Wait - Done
    * Create and Go - After MVP
  * Extra errors - done except for permissions / read-only
* Change from trait enum to trait objects. Done.
* Rough outline of MiB compiler / code generator - Started, both python and rust.
* Using logging rather than println! - Done
* Simplistic permissions model - Done, maybe too simple!
* Get-bulk - Done, but error handling is hope and wishful thinking
* Refactor into library plus example(s) - Done
* Refactor compiler using classes - Won't do, rust / nom compiler is now main line.
* At least two MIB fairly complete implementations that are not just stubs:
  * SNMPv2  - started, mostly done
  * SNMP-USER-BASED-SM - started, no password change or user creation from templates yet.
* Debug AuthNoPriv mode, snmpwalk gives Authorization errors - Done!

## After MVP

* no panics in run time loop
* more hash / cipher choices (at least SHA-256, maybe AES-256, but no standard for that) - RFC 7630
* View model and user mapping to views
* Multiple contexts - separate Oid maps?
* Traps / Informs
* Augments support in compiler and Rust code

