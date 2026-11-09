package uk.ac.ravensbourne.casevault.repository;

import java.util.UUID;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import uk.ac.ravensbourne.casevault.domain.CaseAssignment;

/** Retention-only deletion support for assignment rows before a case is hard-deleted. */
public interface CaseAssignmentRepository extends JpaRepository<CaseAssignment, UUID> {
    Optional<CaseAssignment> findByCaseRecordIdAndAnalystId(UUID caseId, UUID analystId);
    long deleteByCaseRecordId(UUID caseId);
}
