package uk.ac.ravensbourne.casevault.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;
import uk.ac.ravensbourne.casevault.service.CaseAccessService;

/** ArchUnit guard: every explicitly marked public case operation must invoke the central access gate. */
class CaseAccessArchitectureRuleTest {
    @Test
    void tAuthzArch003EveryMarkedCaseOperationCallsCaseAccessService() {
        var classes = new ClassFileImporter().importPackages(
                "uk.ac.ravensbourne.casevault.service", "uk.ac.ravensbourne.casevault.report");
        var markedMethods = classes.stream()
                .flatMap(type -> type.getMethods().stream())
                .filter(method -> Modifier.isPublic(method.reflect().getModifiers()))
                .filter(method -> method.isAnnotatedWith(RequiresCaseAccess.class))
                .toList();

        assertFalse(markedMethods.isEmpty(), "Case operations must opt into the central access marker");
        for (JavaMethod method : markedMethods) {
            boolean invokesAccessService = method.getMethodCallsFromSelf().stream()
                    .anyMatch(call -> call.getTargetOwner().isAssignableTo(CaseAccessService.class));
            assertTrue(invokesAccessService, () -> method.getFullName()
                    + " is marked @RequiresCaseAccess but does not call CaseAccessService");
        }
    }
}
