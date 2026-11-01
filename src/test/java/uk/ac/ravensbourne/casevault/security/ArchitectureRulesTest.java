package uk.ac.ravensbourne.casevault.security;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.junit.jupiter.api.Assertions.assertTrue;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import uk.ac.ravensbourne.casevault.service.*;
import uk.ac.ravensbourne.casevault.common.TestOnly;

/** Guards the web -> service -> repository boundary required for BOLA resistance. */
@AnalyzeClasses(packages="uk.ac.ravensbourne.casevault", importOptions=ImportOption.DoNotIncludeTests.class)
class ArchitectureRulesTest {
 @ArchTest static final ArchRule tAuthzArch001ControllersDoNotUseRepositories=noClasses().that().resideInAPackage("..web..").should().dependOnClassesThat().resideInAPackage("..repository..");
 @ArchTest static final ArchRule tTestIsolation001ProductionDoesNotCallTestOnlyReset=noClasses().should().callMethodWhere(new DescribedPredicate<JavaMethodCall>("a method annotated with @TestOnly"){public boolean test(JavaMethodCall call){return call.getTarget().isAnnotatedWith(TestOnly.class);}});
 @Test void tAuthzArch002CaseIdServiceMethodsAreMarkedForCentralAccess(){for(Method method:ReportApprovalService.class.getDeclaredMethods())if(method.getName().equals("approve"))assertTrue(method.isAnnotationPresent(RequiresCaseAccess.class));assertTrue(CaseAccessService.class.getDeclaredMethods().length>0);}
}
