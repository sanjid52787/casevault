package uk.ac.ravensbourne.casevault.service;

import org.springframework.stereotype.Service;
import uk.ac.ravensbourne.casevault.domain.Role;
import uk.ac.ravensbourne.casevault.repository.CaseRepository;
import uk.ac.ravensbourne.casevault.security.UserPrincipal;

/** Builds role-scoped dashboard data without exposing case records outside service-layer scope. */
@Service
public class DashboardService {
    private final CaseRepository cases;

    public DashboardService(CaseRepository cases) {
        this.cases = cases;
    }

    public DashboardSummary summary(UserPrincipal principal) {
        return switch (Role.valueOf(principal.role())) {
            case CLIENT_USER -> new DashboardSummary("Your cases", cases.countByOrganisationId(principal.organisationId()),
                    "Open your cases", "/cases", null, null);
            case SECURITY_ANALYST -> new DashboardSummary("Assigned cases", cases.countAssignedTo(principal.id()),
                    "Open assigned cases", "/cases", null, null);
            case CASE_MANAGER -> new DashboardSummary("Unassigned cases", cases.countUnassigned(),
                    "Open cases", "/cases", "Open cases", cases.countOpen());
            case AUDITOR_ADMIN -> new DashboardSummary("Administrative access", 0,
                    "Review audit events and account activity", "/admin/audit", "System health", null);
        };
    }

    public record DashboardSummary(String primaryLabel, long primaryCount, String primaryAction, String primaryHref,
                                   String secondaryLabel, Long secondaryCount) { }
}
