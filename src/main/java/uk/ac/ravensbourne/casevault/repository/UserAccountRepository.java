package uk.ac.ravensbourne.casevault.repository;
import java.util.*; import org.springframework.data.jpa.repository.JpaRepository; import uk.ac.ravensbourne.casevault.domain.UserAccount;
public interface UserAccountRepository extends JpaRepository<UserAccount,UUID> { Optional<UserAccount> findByEmailAndOrganisationId(String email, UUID organisationId); }
