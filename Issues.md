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
  * Keeper - OK
  * Usm - 2
  * Privacy - no test cases in RFCs.
  * Agent  Hardest, needs mocks etc.
* Debug /Fix snmpwalk  - done?
* Table model
  * Integer indices in column 1 - Done
    * Get - Done
    * Set existing cells - Done
  * Multicolumn indices: Integers, strings and addresses - done.
  * Text-Convention range checking (lookup done for DEFVAL)
  * Default Values - mostly done
  * Augment tables - FIXME - wrong implementation, needs Rust support to do right, do after MVP
  * Row management via row status column
    * Delete
    * Active / "not in service" switching
    * Create and Wait
    * Create and Go
  * Extra errors - done except for permissions / read-only
* Change from trait enum to trait objects. Done.
* Rough outline of MiB compiler / code generator - Started
* Using logging rather than println! - Done
* Simplistic permissions model
* Get-bulk - Done, but error handling is hope and wishful thinking
* Remote user support as example of table model
* Refactor into library plus example(s) - Done
* Refactor compiler using classes

## After MVP

* no panics in run time loop
* more hash / cipher choices (at least SHA-256, AES-256) - RFC 7630
* View model and user mapping to views
* Multiple contexts - separate Oid maps?
* Traps / Informs
* Augments support in compiler and Rust code

## Blue Sky

* Proper MIB compiler, using nom!
