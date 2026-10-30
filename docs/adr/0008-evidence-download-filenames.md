# ADR 0008: Use generated UUID attachment filenames for evidence downloads

## Context

Evidence metadata retains a sanitised client-supplied filename for display. Reflecting that value in
the `Content-Disposition` header would make a browser-facing response depend on user-controlled
metadata and risks future header-encoding mistakes or misleading filename behaviours.

## Options considered

1. Return the sanitised display filename as the attachment name.
2. Return a generated evidence UUID as the attachment name.
3. Omit the attachment filename.

## Decision

Downloads use `evidence-<evidence UUID>` with RFC 5987 UTF-8 encoding and always send
`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`.
The original sanitised name remains database display metadata only and is never a storage path or a
download header input.

## Consequences

This reduces exposure of client-controlled filenames and removes a class of content-disposition
injection and content-type confusion mistakes. Users receive a less friendly default filename and
may rename a downloaded file locally. The case UI can show the sanitised display name separately.
