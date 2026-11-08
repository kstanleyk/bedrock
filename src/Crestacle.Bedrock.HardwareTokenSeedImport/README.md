# Crestacle.Bedrock.HardwareTokenSeedImport

Vendor-neutral parsing of OATH HOTP/TOTP hardware token seed-file exports into a
normalized `SeedRecord` (secret, algorithm, digits, period, serial number), for
self-hosted MFA enrollment with `Crestacle.Bedrock` — no dependency on a vendor's
hosted validation service.

## What's in this package

- **`ISeedFileParser`** — the abstraction; one implementation per manufacturer's export format
- **`SeedRecord`** — the normalized shape consuming code maps onto its own credential model
- **`Vendors.ProtectimusSeedFileParser`** — parses Protectimus order exports

## Status

- `ProtectimusSeedFileParser` is a stub — Protectimus's seed-file export format
  (CSV vs. PSKC XML, field names, secret encoding) hasn't been confirmed against
  a real order export yet.
