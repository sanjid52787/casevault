package uk.ac.ravensbourne.casevault.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Severity;

public interface CaseRepository extends JpaRepository<CaseRecord, UUID> {
    Optional<CaseRecord> findByIdAndOrganisationId(UUID id, UUID organisationId);
    List<CaseRecord> findByOrganisationIdAndOwnerAnalystId(UUID organisationId, UUID ownerAnalystId);

    @Query("select count(a)>0 from CaseAssignment a where a.caseRecord.id=:caseId and a.analyst.id=:analystId")
    boolean existsAssignment(@Param("caseId") UUID caseId, @Param("analystId") UUID analystId);

    @Query("""
            select c from CaseRecord c where c.organisation.id=:organisationId
            and (:query is null or lower(c.title) like :query escape '\\' or lower(c.description) like :query escape '\\')
            and (:category is null or c.category=:category) and (:severity is null or c.severity=:severity)
            and (:status is null or c.status=:status) and (:ownerId is null or c.ownerAnalyst.id=:ownerId)
            and (:from is null or c.createdAt>=:from) and (:toExclusive is null or c.createdAt<:toExclusive)
            """)
    Page<CaseRecord> searchClient(@Param("organisationId") UUID organisationId, @Param("query") String query,
                                  @Param("category") Category category, @Param("severity") Severity severity,
                                  @Param("status") CaseStatus status, @Param("ownerId") UUID ownerId,
                                  @Param("from") Instant from, @Param("toExclusive") Instant toExclusive,
                                  Pageable pageable);

    @Query("""
            select c from CaseRecord c where exists (select a from CaseAssignment a where a.caseRecord=c and a.analyst.id=:analystId)
            and (:query is null or lower(c.title) like :query escape '\\' or lower(c.description) like :query escape '\\')
            and (:category is null or c.category=:category) and (:severity is null or c.severity=:severity)
            and (:status is null or c.status=:status) and (:ownerId is null or c.ownerAnalyst.id=:ownerId)
            and (:from is null or c.createdAt>=:from) and (:toExclusive is null or c.createdAt<:toExclusive)
            """)
    Page<CaseRecord> searchAssigned(@Param("analystId") UUID analystId, @Param("query") String query,
                                    @Param("category") Category category, @Param("severity") Severity severity,
                                    @Param("status") CaseStatus status, @Param("ownerId") UUID ownerId,
                                    @Param("from") Instant from, @Param("toExclusive") Instant toExclusive,
                                    Pageable pageable);

    @Query("""
            select c from CaseRecord c where
            (:query is null or lower(c.title) like :query escape '\\' or lower(c.description) like :query escape '\\')
            and (:category is null or c.category=:category) and (:severity is null or c.severity=:severity)
            and (:status is null or c.status=:status) and (:ownerId is null or c.ownerAnalyst.id=:ownerId)
            and (:from is null or c.createdAt>=:from) and (:toExclusive is null or c.createdAt<:toExclusive)
            """)
    Page<CaseRecord> searchManaged(@Param("query") String query, @Param("category") Category category,
                                   @Param("severity") Severity severity, @Param("status") CaseStatus status,
                                   @Param("ownerId") UUID ownerId, @Param("from") Instant from,
                                   @Param("toExclusive") Instant toExclusive, Pageable pageable);
}
