# MedDefense Health Systems: The Cryptographic Foundation

Where Project 1x03 designed the strategy and secured the budget, this project builds the layer every other control depends on: cryptography actually configured correctly. Starting from a full data protection inventory that found only 2 of 21 data-state combinations adequately protected, this project works hands-on with OpenSSL and LUKS to encrypt the patient database at rest, fix the patient portal's TLS configuration before its certificate expires, secure DICOM imaging traffic, harden Active Directory's authentication protocols, and properly design encrypted, key-isolated backup storage, connecting every cryptographic primitive learned directly back to a specific MedDefense system, vulnerability, or requirement identified in Projects 1x00 through 1x03.

See `0-crypto_inventory.md` through `22-implementation_playbook.md` for the full deliverable set.

