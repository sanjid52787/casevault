# ADR 0004: Tink AEAD file encryption

## Context
Evidence needs authenticated encryption at rest without custom cryptography.
## Options considered
Plain filesystem encryption; custom AES; Google Tink AES-GCM AEAD with keyset supplied as a secret.
## Decision
Use Tink AES-GCM and keep the keyset outside source control.
## Consequences
Ciphertext integrity is authenticated; key loss prevents recovery and key rotation must be designed.
