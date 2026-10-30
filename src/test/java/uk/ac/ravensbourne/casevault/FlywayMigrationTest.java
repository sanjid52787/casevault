package uk.ac.ravensbourne.casevault;
import static org.junit.jupiter.api.Assertions.assertEquals; import org.flywaydb.core.Flyway; import org.junit.jupiter.api.Test;
class FlywayMigrationTest { @Test void tSchema001MigratesOnPostgresCompatibleH2(){var flyway=Flyway.configure().dataSource("jdbc:h2:mem:flyway;MODE=PostgreSQL;DB_CLOSE_DELAY=-1","sa","").locations("classpath:db/migration").load();assertEquals(4,flyway.migrate().migrationsExecuted);} }
