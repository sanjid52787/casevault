package uk.ac.ravensbourne.casevault.audit;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*; import java.util.concurrent.*;
import org.junit.jupiter.api.*; import org.springframework.beans.factory.annotation.*; import org.springframework.boot.test.context.SpringBootTest; import org.springframework.jdbc.core.JdbcTemplate; import org.springframework.test.context.ActiveProfiles; import uk.ac.ravensbourne.casevault.domain.Role; import uk.ac.ravensbourne.casevault.security.UserPrincipal;

@SpringBootTest @ActiveProfiles("test") class PersistentAuditServiceTest {
 @Autowired PersistentAuditService audit; @Autowired JdbcTemplate jdbc;
 private UserPrincipal actor(){return new UserPrincipal(UUID.randomUUID(),UUID.randomUUID(),"audit@example.test","",Role.AUDITOR_ADMIN.name(),true,false);}
 @BeforeEach void reset(){jdbc.update("DELETE FROM audit_events");jdbc.update("UPDATE audit_chain_head SET last_event_id=NULL,last_hash=NULL WHERE singleton=TRUE");}
 @Test void tAudit001AppendAndChainLink(){audit.record(actor(),"CASE_VIEWED","CASE",UUID.randomUUID(),"case-viewed");audit.record(actor(),"SEARCH_PERFORMED","CASE",null,"search-performed");assertTrue(audit.verifyChain().valid());assertEquals(2,jdbc.queryForObject("SELECT COUNT(*) FROM audit_events",Integer.class));}
 @Test void tAudit002TamperingDetected(){audit.record(actor(),"CASE_VIEWED","CASE",UUID.randomUUID(),"case-viewed");long id=jdbc.queryForObject("SELECT MIN(id) FROM audit_events",Long.class);jdbc.update("UPDATE audit_events SET action='TAMPERED' WHERE id=?",id);var result=audit.verifyChain();assertFalse(result.valid());assertEquals(id,result.firstBrokenEventId().orElseThrow());}
 @Test void tAudit003ConcurrentAppendsKeepChainValid() throws Exception {var pool=Executors.newFixedThreadPool(4);var jobs=new ArrayList<Callable<Void>>();for(int i=0;i<12;i++)jobs.add(()->{audit.record(actor(),"CASE_VIEWED","CASE",UUID.randomUUID(),"case-viewed");return null;});pool.invokeAll(jobs);pool.shutdown();assertTrue(audit.verifyChain().valid());assertEquals(12,jdbc.queryForObject("SELECT COUNT(*) FROM audit_events",Integer.class));}
 @Test void tAudit004NoSecretsInDetails(){assertThrows(IllegalArgumentException.class,()->audit.record(actor(),"CASE_VIEWED","CASE",UUID.randomUUID(),"password-value"));assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM audit_events",Integer.class));}
}
