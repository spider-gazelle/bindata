# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Includes a breaking change (the per-type field shortcut removal below), so the
next release is a new major.

### Security

- Cap generic-DSL allocations with a `max_content_length` on the `BinData` base
  (default `0` = unlimited), propagated to nested children, and bound a
  non-advancing `variable_array` loop. (#46)
- Reject a negative `length:` / `skip` callback result, which used to silently
  read nothing or desync the stream. (#45)
- Add a propagated `max_depth` (default `100`) so a recursive `children` walk
  raises `ASN1::MaxDepthExceeded` instead of overflowing the consumer's stack on
  a deeply nested message. (#49)

### Removed

- **Breaking:** removed the generated per-type field shortcut macros
  (`uint8`/`string`/`bytes`/…). Declare fields with `field name : Type`. (#39)

### Added

- Extend the "`endian` must be declared before a `group`" ordering guard to
  `bit_field`. (#36)

### Fixed

- ASN.1 INTEGER codec: reject content wider than 8 bytes, handle `Int64::MIN`,
  and fix negative sign-padding. (#40)
- `tag_number=` rejects out-of-range tags (0..30) with a typed `ASN1::InvalidTag`
  instead of truncating to 5 bits or leaking an `OverflowError`. (#48)
- Three correctness bugs: `value:` integer coercion silently truncating, the
  null-terminated `String` read dropping a byte, and `set_hexstring` corrupting
  its input. (#47)
- Stop prepending a `0x01` sentinel byte to indefinite-length payloads. (#43)
- Raise a typed error on truncated indefinite-length content. (#35)
- Replace bare `raise "string"` calls with typed errors. (#38)

### Performance

- Decode bit fields up to 16 bits without a per-field `IO::Memory`. (#41)

### Documentation / Tests

- Cover previously-untested typed accessors. (#42)
- Document `skip` / `read_next` and the renamed `ASN1::Error` names. (#34)

## [3.0.0] - 2026-06-26

The first release of the hardening effort (#19–#33): a base-128 OID codec,
`value:` procs on `Float` fields, DSL macro/method name reservation, a BER
content-length cap, a fiber-safe `BitField`, a bounded extended-identifier
parser, corrected BER length short/long-form boundaries with `Int32`-overflow
rejection, a mise-based CI workflow, public API documentation, an expanded
README, a consolidated `ASN1::Error` hierarchy, little-endian bit fields,
streaming `remaining_bytes`, the `endian`-after-`group` guard, and the `skip`
field.

See the [release notes](https://github.com/spider-gazelle/bindata/releases/tag/v3.0.0)
for the full per-PR list.

[Unreleased]: https://github.com/spider-gazelle/bindata/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/spider-gazelle/bindata/releases/tag/v3.0.0
