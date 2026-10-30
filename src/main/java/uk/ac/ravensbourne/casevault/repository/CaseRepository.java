package uk.ac.ravensbourne.casevault.repository;
import java.util.*; import org.springframework.data.jpa.repository.JpaRepository; import uk.ac.ravensbourne.casevault.domain.CaseRecord;
public interface CaseRepository extends JpaRepository<CaseRecord,UUID> { Optional<CaseRecord> findByIdAndOrganisationId(UUID id, UUID organisationId); List<CaseRecord> findByOrganisationIdAndOwnerAnalystId(UUID organisationId, UUID ownerAnalystId); }
