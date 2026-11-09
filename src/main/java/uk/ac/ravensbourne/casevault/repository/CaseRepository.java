package uk.ac.ravensbourne.casevault.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;

public interface CaseRepository extends JpaRepository<CaseRecord, UUID>, JpaSpecificationExecutor<CaseRecord> {
    @Query("select c from CaseRecord c where c.id=:id and c.organisation.id=:organisationId and c.deletedAt is null")
    Optional<CaseRecord> findByIdAndOrganisationId(@Param("id") UUID id, @Param("organisationId") UUID organisationId);
    @Query("select c from CaseRecord c where c.id=:id and c.deletedAt is null")
    Optional<CaseRecord> findActiveById(@Param("id") UUID id);
    @Query("select c from CaseRecord c where c.organisation.id=:organisationId and c.ownerAnalyst.id=:ownerAnalystId and c.deletedAt is null")
    List<CaseRecord> findByOrganisationIdAndOwnerAnalystId(@Param("organisationId") UUID organisationId, @Param("ownerAnalystId") UUID ownerAnalystId);
    @Query("select count(c) from CaseRecord c where c.organisation.id=:organisationId and c.deletedAt is null")
    long countByOrganisationId(@Param("organisationId") UUID organisationId);

    @Query("select count(c) from CaseRecord c where c.deletedAt is null and exists (select a from CaseAssignment a where a.caseRecord=c and a.analyst.id=:analystId)")
    long countAssignedTo(@Param("analystId") UUID analystId);

    @Query("select count(c) from CaseRecord c where c.deletedAt is null and c.ownerAnalyst is null")
    long countUnassigned();

    @Query("select count(c) from CaseRecord c where c.deletedAt is null and c.status <> uk.ac.ravensbourne.casevault.domain.CaseStatus.CLOSED")
    long countOpen();

    @Query("select count(a)>0 from CaseAssignment a where a.caseRecord.id=:caseId and a.analyst.id=:analystId")
    boolean existsAssignment(@Param("caseId") UUID caseId, @Param("analystId") UUID analystId);

    @Query("select c.id from CaseRecord c where c.status=uk.ac.ravensbourne.casevault.domain.CaseStatus.CLOSED and c.deletedAt is null and c.retentionUntil < :now")
    List<UUID> findSoftDeleteCandidates(@Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update CaseRecord c set c.deletedAt=:deletedAt where c.id=:id and c.status=uk.ac.ravensbourne.casevault.domain.CaseStatus.CLOSED and c.deletedAt is null and c.retentionUntil < :now")
    int claimSoftDelete(@Param("id") UUID id, @Param("now") Instant now, @Param("deletedAt") Instant deletedAt);

    @Query("select c.id from CaseRecord c where c.status=uk.ac.ravensbourne.casevault.domain.CaseStatus.CLOSED and c.deletedAt is not null and c.deletedAt < :hardDeleteBefore")
    List<UUID> findHardDeleteCandidates(@Param("hardDeleteBefore") Instant hardDeleteBefore);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from CaseRecord c where c.id=:id and c.status=uk.ac.ravensbourne.casevault.domain.CaseStatus.CLOSED and c.deletedAt is not null and c.deletedAt < :hardDeleteBefore")
    Optional<CaseRecord> lockHardDeleteCandidate(@Param("id") UUID id, @Param("hardDeleteBefore") Instant hardDeleteBefore);
}
