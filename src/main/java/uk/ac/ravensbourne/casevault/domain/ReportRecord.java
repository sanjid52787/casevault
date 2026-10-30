package uk.ac.ravensbourne.casevault.domain;

import jakarta.persistence.*;
import java.util.UUID;

/** Minimal report aggregate used to enforce manager/author separation of duties (CWE-863). */
@Entity @Table(name="reports")
public class ReportRecord {
    @Id private UUID id;
    @ManyToOne(optional=false) @JoinColumn(name="case_id") private CaseRecord caseRecord;
    @ManyToOne(optional=false) @JoinColumn(name="organisation_id") private Organisation organisation;
    @Column(nullable=false) private int version;
    @Column(nullable=false) private String content;
    @Enumerated(EnumType.STRING) @Column(nullable=false) private ReportStatus status;
    @ManyToOne(optional=false) @JoinColumn(name="generated_by") private UserAccount generatedBy;
    @ManyToOne @JoinColumn(name="approved_by") private UserAccount approvedBy;
    protected ReportRecord() { }
    public ReportRecord(UUID id, CaseRecord caseRecord, Organisation organisation, UserAccount generatedBy) { this.id=id; this.caseRecord=caseRecord; this.organisation=organisation; this.generatedBy=generatedBy; this.version=1; this.content="synthetic report"; this.status=ReportStatus.DRAFT; }
    public UUID getId(){return id;} public CaseRecord getCaseRecord(){return caseRecord;} public UserAccount getGeneratedBy(){return generatedBy;}
    public void approve(UserAccount manager){this.status=ReportStatus.APPROVED;this.approvedBy=manager;}
}
