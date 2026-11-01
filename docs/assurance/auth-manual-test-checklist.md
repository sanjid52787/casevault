# Authentication and session manual checklist

| Test | Steps | Expected | WSTG mapping |
|---|---|---|---|
| T-AUTH-001 | Sign in with an enabled synthetic account. | New authenticated session and rotated ID. | WSTG-ATHN-02 |
| T-AUTH-002/003 | Submit wrong password and unknown email. | Same “Invalid credentials” response. | WSTG-ATHN-03 |
| T-AUTH-004/005 | Repeat failures; try disabled account. | Temporary lock / authentication denied. | WSTG-ATHN-03 |
| T-AUTH-006/008 | POST logout without/with CSRF; replay old cookie. | CSRF denied; valid logout invalidates session. | WSTG-SESS-03 |
| T-AUTH-007 | Compare session ID before/after login. | ID changes. | WSTG-SESS-04 |
| T-AUTH-009/010 | Change password using weak and valid values; inspect DB only in authorised local test. | Policy rejects weak input; Argon2 hash only. | WSTG-ATHN-07 |
| T-SESS-001..003 | Wait idle timeout; disable user; inspect Set-Cookie. | Expiry/revocation; HttpOnly, Secure, SameSite=Strict. | WSTG-SESS-02, WSTG-SESS-03 |
