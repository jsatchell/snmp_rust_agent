# Issues to MVP

* Privacy - Done
* Swap to Vec for Oid table - Done
* Get-next - Done 
* Trait for OidKeeper, and sample Impls - Done
* Change OidMap type to OidKeeper - Done
* Set (for scalars only) - Done
* Correct error response for simplest cases - Made a start. Missing below
   * Decode Error
   * Authentication Error
   * Permission Errors
   * Wrong encoding / size
* Debug /Fix snmpwalk ?
* Table model
   * Integer indices in column 1 - Done
      * Get - Done
      * Set existing cells - Done
   * Row management via row status column
      * Delete
      * Active / "not in service" switching
      * Create and Wait
      * Create and Go
   * General indices
   * Extra errors
* Get-bulk - only interesting in table case
* Remote user support as example of table model
* Refactor into library plus example(s) - Done

## After MVP:
* more hash / cipler choices (at least SHA-256, AES-256)
* View model and user mapping to views
* Multiple contexts - separate Oid maps?

## Blue Sky
* MIB compiler!
