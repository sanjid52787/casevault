package uk.ac.ravensbourne.casevault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CaseVaultApplication {
    public static void main(String[] args) {
        SpringApplication.run(CaseVaultApplication.class, args);
    }
}
