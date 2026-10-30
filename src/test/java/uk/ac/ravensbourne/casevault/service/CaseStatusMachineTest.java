package uk.ac.ravensbourne.casevault.service;
import static org.junit.jupiter.api.Assertions.*; import org.junit.jupiter.api.Test; import uk.ac.ravensbourne.casevault.domain.CaseStatus;
class CaseStatusMachineTest { @Test void tWorkflow001AllowsOnlyDefinedTransitions(){assertTrue(CaseStatusMachine.permits(CaseStatus.NEW,CaseStatus.TRIAGED));assertFalse(CaseStatusMachine.permits(CaseStatus.NEW,CaseStatus.CLOSED));assertThrows(IllegalArgumentException.class,()->CaseStatusMachine.requirePermitted(CaseStatus.CLOSED,CaseStatus.NEW));} }
