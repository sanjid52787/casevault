# Test plan

Automated test identifiers and expected Surefire report paths are indexed in `evidence-index.md`. Tests use H2
in PostgreSQL compatibility mode and only synthetic/inert data. PostgreSQL/Testcontainers locking coverage and
deployment/supply-chain tests remain planned.

Spring integration tests share the `jdbc:h2:mem:casevault` database; any test that creates organisations,
users or cases must use `TestDataCleaner` before and after each test to remove fixtures in foreign-key order.
