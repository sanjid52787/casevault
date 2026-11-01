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
    public ReportRecord(UUID id, CaseRecord caseRecord, Organisation organisation, UserAccount generatedBy) { this(id,caseRecord,organisation,generatedBy,1,"synthetic report"); }
    public ReportRecord(UUID id, CaseRecord caseRecord, Organisation organisation, UserAccount generatedBy,int version,String content) { this.id=id; this.caseRecord=caseRecord; this.organisation=organisation; this.generatedBy=generatedBy; this.version=version; this.content=content; this.status=ReportStatus.DRAFT; }
    public UUID getId(){return id;} public CaseRecord getCaseRecord(){return caseRecord;} public UserAccount getGeneratedBy(){return generatedBy;} public int getVersion(){return version;} public String getContent(){return content;} public ReportStatus getStatus(){return status;}
    public void submit(){if(status!=ReportStatus.DRAFT)throw new IllegalStateException("Invalid report workflow");status=ReportStatus.SUBMITTED;}
    public void approve(UserAccount manager){if(status!=ReportStatus.SUBMITTED)throw new IllegalStateException("Only submitted reports can be approved");if(generatedBy.getId().equals(manager.getId()))throw new IllegalArgumentException("Report generator cannot approve their own report");this.status=ReportStatus.APPROVED;this.approvedBy=manager;}
}
