package uk.ac.ravensbourne.casevault.repository;

import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;
import uk.ac.ravensbourne.casevault.domain.CaseAssignment;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.CaseStatus;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Severity;

/**
 * Builds {@link Specification} predicates for case search queries, adding a predicate
 * only when the filter value is present so that null parameters are never sent to the
 * database. This avoids PostgreSQL's {@code could not determine data type of parameter}
 * error that occurs with the {@code :param IS NULL OR col = :param} JPQL pattern
 * (CWE-1188). All values are bound via the Criteria API; no string concatenation.
 */
public final class CaseSpecifications {

    private CaseSpecifications() { }

    /** Excludes soft-deleted cases — required on every query. */
    public static Specification<CaseRecord> notDeleted() {
        return (root, query, cb) -> cb.isNull(root.get("deletedAt"));
    }

    /** Client tenant isolation: only cases belonging to the given organisation. */
    public static Specification<CaseRecord> clientScope(UUID organisationId) {
        return (root, query, cb) -> cb.equal(root.get("organisation").get("id"), organisationId);
    }

    /** Analyst assignment scoping: only cases with a matching CaseAssignment row. */
    public static Specification<CaseRecord> assignedScope(UUID analystId) {
        return (root, query, cb) -> {
            Subquery<UUID> subquery = query.subquery(UUID.class);
            Root<CaseAssignment> assignment = subquery.from(CaseAssignment.class);
            subquery.select(assignment.get("caseRecord").get("id"));
            subquery.where(cb.equal(assignment.get("analyst").get("id"), analystId));
            return cb.in(root.get("id")).value(subquery);
        };
    }

    /** Free-text search across title and description with LIKE wildcard escaping. */
    public static Specification<CaseRecord> queryLike(String pattern) {
        return (root, query, cb) -> cb.or(
                cb.like(cb.lower(root.get("title")), pattern, '\\'),
                cb.like(cb.lower(root.get("description")), pattern, '\\')
        );
    }

    public static Specification<CaseRecord> categoryEquals(Category category) {
        return (root, query, cb) -> cb.equal(root.get("category"), category);
    }

    public static Specification<CaseRecord> severityEquals(Severity severity) {
        return (root, query, cb) -> cb.equal(root.get("severity"), severity);
    }

    public static Specification<CaseRecord> statusEquals(CaseStatus status) {
        return (root, query, cb) -> cb.equal(root.get("status"), status);
    }

    public static Specification<CaseRecord> ownerEquals(UUID ownerId) {
        return (root, query, cb) -> cb.equal(root.get("ownerAnalyst").get("id"), ownerId);
    }

    public static Specification<CaseRecord> createdFrom(Instant from) {
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), from);
    }

    public static Specification<CaseRecord> createdBefore(Instant toExclusive) {
        return (root, query, cb) -> cb.lessThan(root.get("createdAt"), toExclusive);
    }
}

