# Phase 5 manual walkthrough

1. Sign in as a synthetic client user, create an incident and confirm it appears only in that organisation's view.
2. Sign in as the assigned analyst, inspect the assigned case and add an investigation note/action.
3. Sign in as a manager, assign an analyst and progress valid statuses; confirm invalid state transitions are rejected. Managers currently view case content but may not add notes/actions.
4. Sign in as an auditor/admin and confirm case content routes return no content while audit/admin metadata is available.
5. Submit a title containing `<script>` and confirm rendered output is escaped; submit SQL/LIKE wildcard text and confirm no extra tenant results are disclosed.
