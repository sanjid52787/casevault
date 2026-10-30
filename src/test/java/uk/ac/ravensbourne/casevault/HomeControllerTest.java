package uk.ac.ravensbourne.casevault;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HomeControllerTest {
    private final MockMvc mockMvc;

    @Autowired
    HomeControllerTest(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void tBaseline001HomeRequiresAuthenticationAndHealthIsAvailable() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }
}
