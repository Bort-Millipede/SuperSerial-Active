# Change Log

## [0.2.1] (2015-1-25)
### Fixed
- Node: IP Address printout (now displaying the correct IPs when files/access entries are downloaded).

### Added
- Node: printouts now preceded by timestamps
- README.md: build procedure

### Changed
- Node: uploaded files/access entries are now saved to [TMP]/SuperSerial directory rather than [TMP] directory.
- Node: uploaded files/access entries are now written to files named "SuperSerial-[CONTEXT_PATH].tmp".
- README.md: updated license
- CHANGELOG.md

## [0.2] (2015-12-30)
### Added
- CHANGELOG.md
- Extender: Support for active detection against Linux and Windows systems running WebSphere.
- Extender: Logic to create platform-based insertion points only under certain conditions, rather than automatically be default.

### Changed
- README.md: include latest description.

## [0.1] (2015-12-09)
### Added
- Extender: Support for active detection of deserialization vulnerabilities against Linux and Windows systems running JBoss (Initial Release).
- Node: Standalone web server component used for vulnerability detection (Initial Release).
