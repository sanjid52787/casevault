package uk.ac.ravensbourne.casevault.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import uk.ac.ravensbourne.casevault.domain.CaseRecord;
import uk.ac.ravensbourne.casevault.domain.Category;
import uk.ac.ravensbourne.casevault.domain.EvidenceFile;
import uk.ac.ravensbourne.casevault.domain.Organisation;
import uk.ac.ravensbourne.casevault.domain.ReportRecord;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.domain.Severity;
import uk.ac.ravensbourne.casevault.domain.UserAccount;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.repository.OrganisationRepository;
import uk.ac.ravensbourne.casevault.repository.ReportRepository;
import uk.ac.ravensbourne.casevault.repository.UserAccountRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;
import uk.ac.ravensbourne.casevault.service.EvidenceService;
import uk.ac.ravensbourne.casevault.support.TestDataCleaner;

/**
 * T-AUTHZ-MATRIX-001: generated HTTP authorisation matrix for all CaseVault content operations.
 * Each row is a real MockMvc request; UI hiding is never used as the decision point.
 */
@SpringBootTest(properties = "casevault.evidence.directory=target/authorisation-matrix-evidence")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthorisationOperationMatrixTest {
    private static final List<String> MATRIX_ROWS = new ArrayList<>();

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OrganisationRepository organisations;
    @Autowired UserAccountRepository users;
    @Autowired CaseRepository cases;
    @Autowired ReportRepository reports;
    @Autowired EvidenceService evidence;
    @Autowired TestDataCleaner cleaner;

    private UserAccount client;
    private UserAccount otherClient;
    private UserAccount analyst;
    private UserAccount manager;
    private UserAccount auditor;
    private CaseRecord clientCase;
    private CaseRecord otherCase;
    private CaseRecord assignedCase;
    private CaseRecord internalCase;

    enum Operation {
        VIEW("view"), CREATE("create"), ASSIGN("assign"), STATUS("status"), NOTE("note"), ACTION("action"),
        EVIDENCE_UPLOAD("evidence upload"), EVIDENCE_DOWNLOAD("evidence download"),
        REPORT_GENERATE("report generate"), REPORT_APPROVE("report approve"), REPORT_DOWNLOAD("report download");
        private final String label;
        Operation(String label) { this.label = label; }
    }

    enum Scope {
        OWN_ORG("own org"), OTHER_ORG("other org"), ASSIGNED("assigned"), UNASSIGNED("unassigned");
        private final String label;
        Scope(String label) { this.label = label; }
    }

    @BeforeAll
    static void resetGeneratedRows() {
        MATRIX_ROWS.clear();
    }

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");
        cleaner.clean();
        Organisation clientOrg = organisations.save(new Organisation(UUID.randomUUID(), "Matrix client"));
        Organisation otherOrg = organisations.save(new Organisation(UUID.randomUUID(), "Matrix other client"));
        Organisation internalOrg = organisations.save(new Organisation(UUID.randomUUID(), "Matrix internal"));
        client = user(clientOrg, "matrix-client@test", Role.CLIENT_USER);
        otherClient = user(otherOrg, "matrix-other@test", Role.CLIENT_USER);
        analyst = user(internalOrg, "matrix-analyst@test", Role.SECURITY_ANALYST);
        manager = user(internalOrg, "matrix-manager@test", Role.CASE_MANAGER);
        auditor = user(internalOrg, "matrix-auditor@test", Role.AUDITOR_ADMIN);
        clientCase = caseFor(clientOrg, client, "Client matrix case");
        otherCase = caseFor(otherOrg, otherClient, "Other matrix case");
        assignedCase = caseFor(clientOrg, client, "Assigned matrix case");
        internalCase = caseFor(internalOrg, manager, "Internal matrix case");
        jdbc.update("INSERT INTO case_assignments(id,case_id,organisation_id,analyst_id,assigned_by) VALUES(?,?,?,?,?)",
                UUID.randomUUID(), assignedCase.getId(), clientOrg.getId(), analyst.getId(), manager.getId());
    }

    @AfterEach
    void tearDown() {
        cleaner.clean();
    }

    static Stream<Arguments> matrix() {
        return Stream.of(Role.values()).flatMap(role -> Stream.of(Operation.values()).flatMap(operation ->
                Stream.of(Scope.values()).map(scope -> Arguments.of(role, operation, scope))));
    }

    @ParameterizedTest(name = "T-AUTHZ-MATRIX-001 {0} {1} {2}")
    @MethodSource("matrix")
    void tAuthzMatrix001EveryRoleOperationAndScope(Role role, Operation operation, Scope scope) throws Exception {
        UserAccount actor = actor(role);
        CaseRecord target = target(role, scope);
        int expected = expectedStatus(role, operation, scope);
        int actual = request(actor, target, operation).andReturn().getResponse().getStatus();
        synchronized (MATRIX_ROWS) {
            MATRIX_ROWS.add("| " + role + " | " + operation.label + " | " + scope.label + " | " + expected
                    + " | " + actual + " | T-AUTHZ-MATRIX-001 |");
        }
        assertEquals(expected, actual, () -> role + " " + operation + " " + scope);
    }

    private ResultActions request(UserAccount actor, CaseRecord target, Operation operation) throws Exception {
        return switch (operation) {
            case VIEW -> mvc.perform(get("/cases/{id}", target.getId()).with(authentication(auth(actor))));
            case CREATE -> mvc.perform(post("/cases").with(authentication(auth(actor))).with(csrf())
                    .param("title", "Matrix created case").param("description", "Synthetic matrix description")
                    .param("category", "OTHER").param("severity", "LOW"));
            case ASSIGN -> mvc.perform(post("/cases/{id}/assign", target.getId()).with(authentication(auth(actor))).with(csrf())
                    .param("analystId", analyst.getId().toString()));
            case STATUS -> mvc.perform(post("/cases/{id}/status", target.getId()).with(authentication(auth(actor))).with(csrf())
                    .param("status", "TRIAGED").param("version", Long.toString(target.getVersion())));
            case NOTE -> mvc.perform(post("/cases/{id}/notes", target.getId()).with(authentication(auth(actor))).with(csrf())
                    .param("body", "Synthetic matrix note").param("clientVisible", "true"));
            case ACTION -> mvc.perform(post("/cases/{id}/actions", target.getId()).with(authentication(auth(actor))).with(csrf())
                    .param("description", "Synthetic matrix action").param("status", "OPEN"));
            case EVIDENCE_UPLOAD -> mvc.perform(multipart("/cases/{id}/evidence", target.getId())
                    .file(new MockMultipartFile("file", "matrix.txt", "application/octet-stream", "matrix".getBytes(StandardCharsets.UTF_8)))
                    .with(authentication(auth(actor))).with(csrf()));
            case EVIDENCE_DOWNLOAD -> {
                EvidenceFile file = evidenceFor(target);
                yield mvc.perform(get("/cases/{caseId}/evidence/{id}", target.getId(), file.getId())
                        .with(authentication(auth(actor))));
            }
            case REPORT_GENERATE -> mvc.perform(post("/cases/{caseId}/reports", target.getId())
                    .with(authentication(auth(actor))).with(csrf()));
            case REPORT_APPROVE -> {
                ReportRecord report = reportFor(target, false);
                yield mvc.perform(post("/cases/{caseId}/reports/{reportId}/approve", target.getId(), report.getId())
                        .with(authentication(auth(actor))).with(csrf()));
            }
            case REPORT_DOWNLOAD -> {
                ReportRecord report = reportFor(target, true);
                yield mvc.perform(get("/cases/{caseId}/reports/{reportId}", target.getId(), report.getId())
                        .with(authentication(auth(actor))));
            }
        };
    }

    private int expectedStatus(Role role, Operation operation, Scope scope) {
        return switch (operation) {
            case VIEW -> canView(role, scope) ? 200 : 404;
            case CREATE -> role == Role.CLIENT_USER ? 302 : 403;
            case ASSIGN, STATUS -> role == Role.CASE_MANAGER ? 302 : 403;
            case NOTE, ACTION -> switch (role) {
                case CASE_MANAGER -> 302;
                case SECURITY_ANALYST -> scope == Scope.ASSIGNED ? 302 : 404;
                case CLIENT_USER, AUDITOR_ADMIN -> 403;
            };
            case EVIDENCE_UPLOAD -> canEvidence(role, scope) ? 201 : 404;
            case EVIDENCE_DOWNLOAD -> canEvidence(role, scope) ? 200 : 404;
            case REPORT_GENERATE -> role == Role.SECURITY_ANALYST ? (scope == Scope.ASSIGNED ? 201 : 404) : 403;
            case REPORT_APPROVE -> role == Role.CASE_MANAGER ? 200 : 403;
            case REPORT_DOWNLOAD -> canDownloadReport(role, scope) ? 200 : 404;
        };
    }

    private boolean canView(Role role, Scope scope) {
        return switch (role) {
            case CLIENT_USER -> scope == Scope.OWN_ORG || scope == Scope.ASSIGNED;
            case SECURITY_ANALYST -> scope == Scope.ASSIGNED;
            case CASE_MANAGER -> true;
            case AUDITOR_ADMIN -> false;
        };
    }

    private boolean canEvidence(Role role, Scope scope) {
        return switch (role) {
            case CLIENT_USER -> scope == Scope.OWN_ORG || scope == Scope.ASSIGNED;
            case SECURITY_ANALYST -> scope == Scope.ASSIGNED;
            case CASE_MANAGER -> true;
            case AUDITOR_ADMIN -> false;
        };
    }

    private boolean canDownloadReport(Role role, Scope scope) {
        return switch (role) {
            case CLIENT_USER -> scope == Scope.OWN_ORG || scope == Scope.ASSIGNED;
            case SECURITY_ANALYST -> scope == Scope.ASSIGNED;
            case CASE_MANAGER -> true;
            case AUDITOR_ADMIN -> false;
        };
    }

    private UserAccount actor(Role role) {
        return switch (role) {
            case CLIENT_USER -> client;
            case SECURITY_ANALYST -> analyst;
            case CASE_MANAGER -> manager;
            case AUDITOR_ADMIN -> auditor;
        };
    }

    private CaseRecord target(Role role, Scope scope) {
        return switch (scope) {
            case OWN_ORG -> role == Role.CLIENT_USER ? clientCase : internalCase;
            case OTHER_ORG, UNASSIGNED -> otherCase;
            case ASSIGNED -> assignedCase;
        };
    }

    private EvidenceFile evidenceFor(CaseRecord target) throws Exception {
        UserAccount seeder = target.getId().equals(otherCase.getId()) ? otherClient
                : target.getId().equals(internalCase.getId()) ? manager : client;
        return evidence.upload(UserPrincipal.from(seeder), target.getId(),
                new MockMultipartFile("file", "seed.txt", "application/octet-stream", "matrix evidence".getBytes(StandardCharsets.UTF_8)));
    }

    private ReportRecord reportFor(CaseRecord target, boolean approve) {
        ReportRecord report = reports.save(new ReportRecord(UUID.randomUUID(), target, target.getOrganisation(), analyst,
                1, "Synthetic report"));
        report.submit();
        if (approve) report.approve(manager);
        return reports.save(report);
    }

    private CaseRecord caseFor(Organisation organisation, UserAccount creator, String title) {
        return cases.save(new CaseRecord(UUID.randomUUID(), organisation, title, "Synthetic", Category.OTHER, Severity.LOW, creator));
    }

    private UserAccount user(Organisation organisation, String email, Role role) {
        return users.save(new UserAccount(UUID.randomUUID(), organisation, email, "hash", role));
    }

    private UsernamePasswordAuthenticationToken auth(UserAccount account) {
        UserPrincipal principal = UserPrincipal.from(account);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }

    @AfterAll
    static void writeMatrix() throws Exception {
        StringBuilder markdown = new StringBuilder("# Generated Phase 4 HTTP authorisation matrix\n\n")
                .append("Generated by `AuthorisationOperationMatrixTest.tAuthzMatrix001EveryRoleOperationAndScope`. ")
                .append("Each row is a MockMvc request; cross-tenant/object denials use 404 where the caller reaches the service layer.\n\n")
                .append("| Role | Operation | Scope | Expected HTTP | Actual HTTP | Test ID |\n")
                .append("|---|---|---|---:|---:|---|\n");
        MATRIX_ROWS.forEach(row -> markdown.append(row).append('\n'));
        Files.writeString(Path.of("docs", "assurance", "authorisation-matrix.md"), markdown.toString(), StandardCharsets.UTF_8);
    }
}
