# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project follows [Semantic Versioning](https://semver.org/).

History: versions 1.x and 2.x were CVEWatch, a Go command-line tool. It is not developed any more. Its releases stay listed on the releases page, and its last commit is tagged `v2-final`. This changelog starts with the Rust rewrite.

## [Unreleased]

### Added

- `unpatched`, a full rewrite in Rust of the Go tool CVEWatch: list the software you run, and a daily GitHub Action tells you only when something you run is affected, what to do, and whether it is being exploited. Keyless and open data only, and no servers: the database is built daily in this repository and published on the rolling `db` release.
- Repository automation: CI on three operating systems, the daily database build, releases with `dist`, a Docker image, and weekly and monthly upkeep (see MAINTAINING.md).

### Changed

- The project, the crate, the command and the config file are now called `unpatched` (was CVEWatch).
- Everything from the Go tool is removed. The last Go commit is tagged `v2-final`.
