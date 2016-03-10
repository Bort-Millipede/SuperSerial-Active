# Change Log

## [0.3] (2016-3-10)
### Fixed
- Node: Standardized output of failed requests ("XXX request denied ...")

### Added
- Extender: Sub-tabs "Node Connection Settings" and "Scan Settings" Under SuperSerial tab.
- Extender: Setting (under SuperSerial->"Scan Settings") to automatically active scan all listed (by Burp) request parameters and JBoss insertion point when performing Active Scan.
- Extender: Allow users to add new or edit/delete existing operating system commands used during Active Scan (under SuperSerial->"Scan Settings").
- Extender: Allow users to re-arrange the order that operating system commands are testing during Active Scan.
- Node: Allow users to remove dynamically-generated contexts by sending DELETE request to context.

### Changed
- Extender: Moved all Node connection configuration settings to SuperSerial->"Node Connection Settings" sub-tab.
- Extender: Moved all Active Scan settings to SuperSerial->"Scan Settings" sub-tab.
- README.md: Updated build procedure
- CHANGELOG.md: Updated

## [0.2.1] (2016-1-25)
### Fixed
- Node: IP Address printout (now displaying the correct IPs when files/access entries are downloaded).

### Added
- Node: printouts now preceded by timestamps
- README.md: build procedure

### Changed
- Node: Uploaded files/access entries are now saved to [TMP]/SuperSerial directory rather than [TMP] directory.
- Node: Uploaded files/access entries are now written to files named "SuperSerial-[CONTEXT_PATH].tmp".
- README.md: Updated license
- CHANGELOG.md

## [0.2] (2015-12-30)
### Added
- CHANGELOG.md
- Extender: Support for active detection against Linux and Windows systems running WebSphere.
- Extender: Logic to create platform-based insertion points only under certain conditions, rather than automatically be default.

### Changed
- README.md: Include latest description.

## [0.1] (2015-12-09)
### Added
- Extender: Support for active detection of deserialization vulnerabilities against Linux and Windows systems running JBoss (Initial Release).
- Node: Standalone web server component used for vulnerability detection (Initial Release).
