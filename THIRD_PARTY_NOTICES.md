# Third-party notices

## Proton Pass CLI

- Project: https://github.com/protonpass/pass-cli
- Version and immutable source commit: `PROTON_PASS_VERSION` and
  `PROTON_PASS_COMMIT` in `Dockerfile`; the image records both as labels.
- License: GNU General Public License v3.0

The upstream Rust source is compiled without modification. The reviewed
Pass 2.4.2 lockfile normalization removes orphaned SDK entries; it preserves
every retained package version, source and checksum. See `upstream-lock-patches`
and `README.md`. The lockfile and generated image SBOM record transitive Rust
dependencies and license metadata.
