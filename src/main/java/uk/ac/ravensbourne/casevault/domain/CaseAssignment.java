package uk.ac.ravensbourne.casevault.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** An explicit analyst assignment used by the service-layer object-access check (CWE-639). */
@Entity
@Table(name = "case_assignments")
public class CaseAssignment {
    @Id
    private UUID id;
    @ManyToOne(optional = false)
    @JoinColumn(name = "case_id")
    private CaseRecord caseRecord;
    @ManyToOne(optional = false)
    @JoinColumn(name = "organisation_id")
    private Organisation organisation;
    @ManyToOne(optional = false)
    @JoinColumn(name = "analyst_id")
    private UserAccount analyst;
    @ManyToOne(optional = false)
    @JoinColumn(name = "assigned_by")
    private UserAccount assignedBy;
    private Instant assignedAt = Instant.now();

    protected CaseAssignment() { }

    public CaseAssignment(UUID id, CaseRecord caseRecord, UserAccount analyst, UserAccount assignedBy) {
        this.id = id;
        this.caseRecord = caseRecord;
        this.organisation = caseRecord.getOrganisation();
        this.analyst = analyst;
        this.assignedBy = assignedBy;
    }
}
