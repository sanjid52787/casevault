package uk.ac.ravensbourne.casevault.service;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.audit.AuditService;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.security.RequiresCaseAccess;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Loads a case and only the notes that the authenticated role may view (CWE-639). */
@Service
public class CaseViewService {
    private final CaseAccessService access;
    private final CaseNoteRepository notes;
    private final AuditService audit;

    public CaseViewService(CaseAccessService access, CaseNoteRepository notes, AuditService audit) {
        this.access = access;
        this.notes = notes;
        this.audit = audit;
    }

    @RequiresCaseAccess
    public CaseDetail view(UserPrincipal principal, UUID caseId) {
        CaseRecord caseRecord = access.requireView(principal, caseId);
        List<CaseNote> visibleNotes = Role.CLIENT_USER.name().equals(principal.role())
                ? notes.findByCaseRecordIdAndClientVisibleTrue(caseId) : notes.findByCaseRecordId(caseId);
        audit.record(principal, "CASE_VIEWED", "CASE", caseId, "case-viewed");
        return new CaseDetail(caseRecord, visibleNotes);
    }

    public record CaseDetail(CaseRecord caseRecord, List<CaseNote> notes) { }
}
