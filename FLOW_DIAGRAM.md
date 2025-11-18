# Application Flow Diagrams

This document contains the Mermaid diagrams describing the searchable encryption application architecture, request flow, and key interactions.

## 1. High-Level Encryption & Search Flow
```mermaid
flowchart LR
  A[User Browser] --> B[Flask App]
  B --> K[Key Derivation PBKDF2]
  B --> P[Extract Text]
  B --> C[Encrypt Fernet]
  B --> T[Create Trapdoor Tokens]
  T --> I[Token -> DocIDs Index]
  C --> S[state.json]
  I --> S
  A --> B
  B --> T2[Compute Trapdoor Search]
  T2 --> I
  I --> R[Results]
```

## 2. Extended Application Flow (All Core Routes)
```mermaid
flowchart TD
  subgraph Client
    U[User] --> UI[Web UI]
  end
  subgraph Backend[Flask App]
    SE[SearchableEncryption Core]
    ST[state.json]
  end

  UI --> UP[Upload Handler]
  UP --> PARSERS[Parse TXT/PDF/DOCX]
  PARSERS --> ENC[Encrypt]
  ENC --> TOKENS[Trapdoor Token Gen]
  TOKENS --> SE
  ENC --> SE
  SE --> ST
  UP --> UI

  UI --> BULK[Bulk Generate]
  BULK --> SYNTH[Synthetic Docs]
  SYNTH --> ENC2[Encrypt Each]
  ENC2 --> SE
  BULK --> UI

  UI --> SRCH[Search Handler]
  SRCH --> TD[Compute Trapdoor]
  TD --> SE
  SE --> SRCH
  SRCH --> UI

  UI --> EFF[Efficiency Test]
  EFF --> SE
  SE --> EFF
  EFF --> UI

  UI --> DEC[Decrypt Handler]
  DEC --> SE
  SE --> DEC
  DEC --> UI

  UI --> RST[Reset Handler]
  RST --> SE
  SE --> ST
  RST --> UI
```

## 3. Sequence Diagram (Upload & Search)
```mermaid
sequenceDiagram
  actor User
  participant Browser
  participant Server
  participant Core

  User->>Browser: choose file & keywords
  Browser->>Server: POST /upload
  Server->>Core: encrypt_document
  Core-->>Server: metadata
  Server-->>Browser: redirect + toast

  User->>Browser: enter keyword
  Browser->>Server: POST /search
  Server->>Core: search_encrypted
  Core-->>Server: doc IDs + time
  Server-->>Browser: JSON results
```

## 4. Legend / Notes
- **Trapdoor Token:** SHA256(index_key || lowercase(keyword)) — deterministic; leaks equality of queries.
- **State Persistence:** `state.json` stores ciphertexts (base64) + token index + metadata.
- **Bulk Generation:** Produces synthetic documents to test scalability quickly.
- **Reset Route:** Secure wipe of in-memory structures and persisted file (requires confirmation word `erase`).

---
For additional architectural evolution (e.g., forward-private SSE, multi-user tenancy, ORAM layers), new nodes can be appended beneath the core encryption component.
