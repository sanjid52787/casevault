package uk.ac.ravensbourne.casevault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.sql.Types;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;

/** Metadata only; uploaded content is ciphertext outside the web root (CWE-434). */
@Entity
@Table(name = "evidence_files")
public class EvidenceFile {
    @Id private UUID id;
    @ManyToOne @JoinColumn(name = "case_id") private CaseRecord caseRecord;
    @ManyToOne @JoinColumn(name = "organisation_id") private Organisation organisation;
    @Column(name = "original_name_sanitised") private String name;
    @Column(name = "stored_name") private UUID storedName;
    @Column(name = "detected_mime") private String mime;
    @Column(name = "size_bytes") private long size;
    /** Matches the schema's fixed-length SHA-256 digest column on PostgreSQL. */
    @JdbcTypeCode(Types.CHAR) @Column(columnDefinition = "char(64)") private String sha256;
    private boolean encrypted;
    @ManyToOne @JoinColumn(name = "uploaded_by") private UserAccount uploadedBy;

    protected EvidenceFile() { }

    public EvidenceFile(UUID id, CaseRecord caseRecord, String name, UUID storedName, String mime,
                        long size, String sha256, UserAccount uploadedBy) {
        this.id = id;
        this.caseRecord = caseRecord;
        this.organisation = caseRecord.getOrganisation();
        this.name = name;
        this.storedName = storedName;
        this.mime = mime;
        this.size = size;
        this.sha256 = sha256;
        this.encrypted = true;
        this.uploadedBy = uploadedBy;
    }

    public UUID getId() { return id; }
    public CaseRecord getCaseRecord() { return caseRecord; }
    public String getName() { return name; }
    public UUID getStoredName() { return storedName; }
    public String getSha256() { return sha256; }
    public long getSize() { return size; }
    public boolean isEncrypted() { return encrypted; }
}
