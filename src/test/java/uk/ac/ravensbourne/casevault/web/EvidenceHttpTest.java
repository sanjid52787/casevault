package uk.ac.ravensbourne.casevault.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.EvidenceFileRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.EvidenceService;

/** HTTP evidence controls: BOLA denial, safe download headers and transfer throttling. */
@SpringBootTest(properties = "casevault.evidence.directory=target/evidence-security-test")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EvidenceHttpTest {
    private static final Path EVIDENCE_ROOT = Path.of("target/evidence-security-test").toAbsolutePath();

    @Autowired MockMvc mvc;
    @Autowired EvidenceService evidence;
    @Autowired EvidenceFileRepository evidenceFiles;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired JdbcTemplate jdbc;

    private UserAccount clientA;
    private UserAccount clientB;
    private UserAccount auditor;
    private CaseRecord caseA;
    private EvidenceFile evidenceA;

    @BeforeEach
    void setUp() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        jdbc.update("DELETE FROM evidence_files");
        jdbc.update("DELETE FROM reports");
        jdbc.update("DELETE FROM remediation_actions");
        jdbc.update("DELETE FROM case_notes");
        jdbc.update("DELETE FROM case_assignments");
        cases.deleteAll();
        users.deleteAll();
        organisations.deleteAll();
        Files.createDirectories(EVIDENCE_ROOT);
        try (var paths = Files.list(EVIDENCE_ROOT)) {
            for (Path path : paths.toList()) Files.deleteIfExists(path);
        }
        Organisation first = organisations.save(new Organisation(UUID.randomUUID(), "Client One"));
        Organisation second = organisations.save(new Organisation(UUID.randomUUID(), "Client Two"));
        Organisation internal = organisations.save(new Organisation(UUID.randomUUID(), "Internal"));
        clientA = save(first, "client-a-evidence@test", Role.CLIENT_USER);
        clientB = save(second, "client-b-evidence@test", Role.CLIENT_USER);
        auditor = save(internal, "auditor-evidence@test", Role.AUDITOR_ADMIN);
        caseA = cases.save(new CaseRecord(UUID.randomUUID(), first, "Case with evidence", "Synthetic case",
                Category.OTHER, Severity.LOW, clientA));
        evidenceA = evidence.upload(UserPrincipal.from(clientA), caseA.getId(),
                new MockMultipartFile("file", "download.txt", "application/octet-stream", "inert download".getBytes()));
    }

    @Test
    void tFile009CrossTenantDownloadReturns404() throws Exception {
        mvc.perform(get("/cases/{caseId}/evidence/{id}", caseA.getId(), evidenceA.getId())
                        .with(authentication(auth(clientB))))
                .andExpect(status().isNotFound());
    }

    @Test
    void tFile010AuditorDownloadDenied() throws Exception {
        mvc.perform(get("/cases/{caseId}/evidence/{id}", caseA.getId(), evidenceA.getId())
                        .with(authentication(auth(auditor))))
                .andExpect(status().isNotFound());
    }

    @Test
    void tFile011DownloadHeadersAreSafe() throws Exception {
        mvc.perform(get("/cases/{caseId}/evidence/{id}", caseA.getId(), evidenceA.getId())
                        .with(authentication(auth(clientA))))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", org.hamcrest.Matchers.containsString("attachment;")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(header().string("Content-Type", org.hamcrest.Matchers.containsString("application/octet-stream")));
    }

    @Test
    void tFile013UploadRateLimitReturns429() throws Exception {
        for (int attempt = 0; attempt < 10; attempt++) {
            mvc.perform(multipart("/cases/{caseId}/evidence", caseA.getId())
                            .file(new MockMultipartFile("file", "rate.txt", "application/octet-stream",
                                    ("inert-" + attempt).getBytes()))
                            .with(authentication(auth(clientA))).with(csrf()))
                    .andExpect(status().isCreated());
        }
        mvc.perform(multipart("/cases/{caseId}/evidence", caseA.getId())
                        .file(new MockMultipartFile("file", "rate.txt", "application/octet-stream", "inert-final".getBytes()))
                        .with(authentication(auth(clientA))).with(csrf()))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    private UserAccount save(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }
}
