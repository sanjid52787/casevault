package uk.ac.ravensbourne.casevault.repository;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import uk.ac.ravensbourne.casevault.domain.CaseNote;

public interface CaseNoteRepository extends JpaRepository<CaseNote, UUID> {
    List<CaseNote> findByCaseRecordIdAndClientVisibleTrue(UUID caseId);
    List<CaseNote> findByCaseRecordId(UUID caseId);
}
