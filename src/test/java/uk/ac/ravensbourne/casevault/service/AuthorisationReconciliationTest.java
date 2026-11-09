package uk.ac.ravensbourne.casevault.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import uk.ac.ravensbourne.casevault.domain.CaseNote;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseNoteRepository;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/** Reconciles the documented note/action policy with the central service policy (CWE-639). */
@SpringBootTest
@ActiveProfiles("test")
class AuthorisationReconciliationTest {
    @Autowired AccessPolicy policy;
    @Autowired CaseViewService views;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired CaseNoteRepository notes;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount auditor;
    private CaseRecord caseRecord;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Organisation clientOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Policy client"));
        Organisation internalOrganisation = organisations.save(new Organisation(UUID.randomUUID(), "Policy internal"));
        client = user(clientOrganisation, "policy-client@test", Role.CLIENT_USER);
        analyst = user(internalOrganisation, "policy-analyst@test", Role.SECURITY_ANALYST);
        manager = user(internalOrganisation, "policy-manager@test", Role.CASE_MANAGER);
        auditor = user(internalOrganisation, "policy-auditor@test", Role.AUDITOR_ADMIN);
        caseRecord = cases.save(new CaseRecord(UUID.randomUUID(), clientOrganisation, "Policy case", "Synthetic",
                Category.OTHER, Severity.LOW, client));
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), caseRecord.getId(), clientOrganisation.getId(), analyst.getId(), manager.getId());
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    @Test
    void tAuthz010AssignedAnalystMayAddNotesAndActions() {
        assertTrue(policy.canAddNote(principal(analyst), caseRecord, true));
        assertTrue(policy.canAddRemediation(principal(analyst), caseRecord, true));
    }

    @Test
    void tAuthz011CaseManagerMayAddNotesAndActions() {
        assertTrue(policy.canAddNote(principal(manager), caseRecord, false));
        assertTrue(policy.canAddRemediation(principal(manager), caseRecord, false));
    }

    @Test
    void tAuthz012ClientMayNotAddNotesOrActions() {
        assertFalse(policy.canAddNote(principal(client), caseRecord, false));
        assertFalse(policy.canAddRemediation(principal(client), caseRecord, false));
    }

    @Test
    void tAuthz013AuditorMayNotAddNotesOrActions() {
        assertFalse(policy.canAddNote(principal(auditor), caseRecord, false));
        assertFalse(policy.canAddRemediation(principal(auditor), caseRecord, false));
    }

    @Test
    void tAuthz014ManagerSeesOnlyClientVisibleNotes() {
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, analyst, "internal analyst note", false));
        notes.save(new CaseNote(UUID.randomUUID(), caseRecord, analyst, "client-visible note", true));

        var detail = views.view(principal(manager), caseRecord.getId());
        assertEquals(1, detail.notes().size());
        assertEquals("client-visible note", detail.notes().getFirst().getBody());
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UserPrincipal principal(UserAccount account) {
        return UserPrincipal.from(account);
    }
}
