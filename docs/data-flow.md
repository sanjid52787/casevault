# Level-1 data-flow diagram

Data labels identify the sensitive payload crossing each boundary. Every transition from browser to app is untrusted until server-side validation and authorisation complete.

```mermaid
flowchart TB
 subgraph TB1[Trust boundary: Internet / browser]
  U[User browser\ncredentials, CSRF, case/evidence requests]
 end
 subgraph TB2[Trust boundary: DMZ / proxy]
  N[nginx TLS terminator\nrequest-size/proxy controls]
 end
 subgraph TB3[Trust boundary: application]
  W[Spring MVC controllers]
  S[Services: AccessPolicy, validation, rate limits, crypto]
  W --> S
 end
 subgraph TB4[Trust boundary: data tier]
  DB[(PostgreSQL\nusers/cases/sessions)]
  AD[(Audit events\nHMAC chain)]
  FS[(Ciphertext file store)]
 end
 subgraph TB5[Trust boundary: CI/CD]
  CI[Build/test/SBOM/scans]
  IMG[Hardened image]
 end
 U -->|HTTPS: credentials, CSRF forms, uploads| N -->|private HTTP| W
 S -->|bound SQL| DB
 S -->|append/read audit| AD
 S -->|AES-GCM ciphertext| FS
 CI -->|reviewed artifact| IMG --> S
```

## Domain model

```mermaid
erDiagram
 ORGANISATIONS ||--o{ USERS : contains
 ORGANISATIONS ||--o{ CASES : owns
 USERS ||--o{ CASES : creates
 USERS ||--o{ CASES : assigned_owner
 CASES ||--o{ CASE_NOTES : has
 CASES ||--o{ REMEDIATION_ACTIONS : has
 CASES ||--o{ EVIDENCE_FILES : has
 CASES ||--o{ REPORTS : has
 USERS ||--o{ SESSIONS : has
 USERS ||--o{ LOGIN_ATTEMPTS : targets
 USERS ||--o{ AUDIT_EVENTS : acts
 ORGANISATIONS { uuid id PK string name }
 USERS { uuid id PK uuid organisation_id FK string role boolean enabled }
 CASES { uuid id PK uuid organisation_id FK uuid owner_id FK string status }
 CASE_NOTES { uuid id PK uuid case_id FK uuid author_id FK string body }
 REMEDIATION_ACTIONS { uuid id PK uuid case_id FK uuid author_id FK string status }
 EVIDENCE_FILES { uuid id PK uuid case_id FK string storage_name string sha256 }
 REPORTS { uuid id PK uuid case_id FK uuid author_id FK uuid approver_id FK }
 AUDIT_EVENTS { uuid id PK string previous_hash string event_hash }
 SESSIONS { string id PK uuid user_id FK datetime expires_at }
 LOGIN_ATTEMPTS { uuid id PK uuid user_id FK datetime occurred_at }
```
