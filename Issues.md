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
  * Permission Errors
  * Wrong encoding / size
* Tests - Started
  * Keeper - OK
  * Usm - 1
  * Privacy
  * Agent  Hardest, needs mocks etc.
* Debug /Fix snmpwalk  - done?
* Table model
  * Integer indices in column 1 - Done
    * Get - Done
    * Set existing cells - Done
  * Multicolumn indices: Integers, strings and addresses - done.
  * Text-Convention range checking
  * Row management via row status column
    * Delete
    * Active / "not in service" switching
    * Create and Wait
    * Create and Go
  * Extra errors - done except for permissions / read-only
* Change from trait enum to trait objects. Done.
* Rough outline of MiB compiler / code generator - Started
* Simplistic permissions model
* Get-bulk - only interesting in table case - Started
* Remote user support as example of table model
* Refactor into library plus example(s) - Done
* Refactor compiler using classes

## After MVP

* more hash / cipler choices (at least SHA-256, AES-256) - RFC 7360
* View model and user mapping to views
* Multiple contexts - separate Oid maps?
* Traps
* Augments support in compiler

## Blue Sky

* Proper MIB compiler, using nom!
