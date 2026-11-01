# ADR 0004: Tink AEAD file encryption

## Context
Evidence needs authenticated encryption at rest without custom cryptography.
## Options considered
Plain filesystem encryption; custom AES; Google Tink AES-GCM AEAD with keyset supplied as a secret.
## Decision
Use Tink AES-GCM with the case ID and evidence-file ID as associated data, and keep the keyset outside source control.
## Consequences
Ciphertext integrity is authenticated; ciphertext swapping between records fails associated-data authentication. Key loss prevents recovery and formal key rotation remains operational work.
