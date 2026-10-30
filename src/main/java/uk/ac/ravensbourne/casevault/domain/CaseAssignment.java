package uk.ac.ravensbourne.casevault.domain;
import jakarta.persistence.*; import java.util.UUID;
@Entity @Table(name="case_assignments") public class CaseAssignment { @Id UUID id; @ManyToOne @JoinColumn(name="case_id") CaseRecord caseRecord; @ManyToOne @JoinColumn(name="analyst_id") UserAccount analyst; }
