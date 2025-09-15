# Security Policy

The team takes security very seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

This is prototype software and is not yet suitable for production use, or deployment on dirty networks.

# Security target

These are targets for production versions - not something the current code yet claims.

* Implementation in 100% safe Rust code. This one is true now!
* Panic is permitted at startup on misconfiguration or resource problems. The agent must not run in a bad configuration! More checks on configuration should be added, especially on handler loading.
* No panics once the event loop starts. Most uses of unwrap()have been commented with reasons why they will always succeed, or don't matter (e.g. in tests), or are permitted as part of the startup. More work is needed on the proofs of success, and more unwraps should be removed by refactoring. If third party handlers are used, they also have to be free of panics at run time.

## Supported Versions

Until the project reaches version 1.0, only the most recent version released on crates.io will be supported - the code is changing quickly, and many bugs are fixed from version to version. If the team are made aware of other projects that depend on this crate, we will consider wider support of versions that are in use.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.0   | :white_check_mark: |

## Reporting a Vulnerability

To report a security issue, please use the GitHub Security Advisory "Report a Vulnerability" tab.

The team will send a response indicating the next steps in handling your report. After the initial reply to your report, the security team will keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

Report security bugs in third-party modules to the person or team maintaining the module.

There isn't a tutorial yet on securing SNMP applications built using the framework, but there should be! There is an issue to write one before we get to version 1.0.
