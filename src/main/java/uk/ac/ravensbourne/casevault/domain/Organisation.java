package uk.ac.ravensbourne.casevault.domain;
import jakarta.persistence.*; import java.time.Instant; import java.util.UUID;
@Entity @Table(name="organisations") public class Organisation { @Id private UUID id; @Column(nullable=false,unique=true) private String name; @Column(nullable=false) private Instant createdAt=Instant.now(); @Column(nullable=false) private Instant updatedAt=Instant.now(); protected Organisation(){} public Organisation(UUID id,String name){this.id=id;this.name=name;} public UUID getId(){return id;} public String getName(){return name;} }
