package uk.ac.ravensbourne.casevault.repository;
import java.util.*; import org.springframework.data.jpa.repository.JpaRepository; import uk.ac.ravensbourne.casevault.domain.Organisation;
public interface OrganisationRepository extends JpaRepository<Organisation,UUID> { Optional<Organisation> findByName(String name); }
