package uk.ac.ravensbourne.casevault.repository;
import java.util.*; import org.springframework.data.jpa.repository.JpaRepository; import uk.ac.ravensbourne.casevault.domain.ReportRecord;
public interface ReportRepository extends JpaRepository<ReportRecord,UUID> { Optional<ReportRecord> findByIdAndCaseRecordId(UUID id,UUID caseId); Optional<ReportRecord> findFirstByCaseRecordIdOrderByVersionDesc(UUID caseId); }
