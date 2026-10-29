# ADR-0004: Safe File Handling, Strict Validation, and Sandboxed Evidence Download

## Status
Accepted

## Context
CaseVault accepts evidence files uploaded by investigators and clients (e.g. log files, packet traces, crash dumps, harmless screenshots). File uploads represent a premier attack vector:
1. Path traversal attacks (`../../evil.sh`).
2. Server-side code execution (uploading `.php`, `.py`, `.exe` into an executable folder).
3. Stored Cross-Site Scripting (XSS) via embedded HTML or malicious SVG files served with executable MIME types.
4. Polyglot files disguised as images but executing as scripts.

## Decision
We implement a multi-layered safe file handling pipeline:
1. **Filename Sanitization:** The original filename is stripped of directory components and sanitized using strict alphanumeric/safe-symbol regular expressions. Files on disk are stored solely under random UUID4 identifiers without user extensions.
2. **Strict Extension Whitelist:** Only approved, inert forensic evidence extensions are accepted (`.txt`, `.log`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.json`, `.csv`, `.pcap`). Executable extensions (`.py`, `.exe`, `.sh`, `.php`, `.svg`, `.html`, `.bat`, etc.) are unconditionally rejected.
3. **Magic Byte / Content Inspection:** File headers are validated against declared MIME types (e.g. checking PNG `\x89PNG\r\n\x1a\n` signatures, PDF `%PDF` headers) to reject disguised binaries or polyglots.
4. **Sandboxed Download Headers:** When evidence is downloaded:
   - Forced download via `Content-Disposition: attachment; filename="sanitized_name"`
   - `Content-Type: application/octet-stream` (or strictly validated binary type)
   - Strict Content Security Policy on the download response: `Content-Security-Policy: sandbox; default-src 'none';`
   - `X-Content-Type-Options: nosniff` to prevent browser MIME-sniffing.
5. **Storage Isolation:** Evidence files are stored outside the web root (`vault_storage/`) and are never served directly by the web server (Nginx/Apache/Django static files). Every download request is authenticated, authorized, logged, and streamed through an application view.

## Consequences
### Positive
- Completely neutralizes stored XSS, MIME confusion attacks, and remote code execution via uploads.
- Evidence files cannot be browsed directly by unauthenticated actors.

### Negative / Trade-offs
- File uploads incur validation overhead and streaming encryption.
- Some niche binary formats require addition to whitelist if needed by IR teams.

