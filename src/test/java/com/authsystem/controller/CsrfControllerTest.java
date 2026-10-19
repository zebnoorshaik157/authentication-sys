
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.csrf.CsrfToken;

class CsrfControllerTest {

    private final CsrfController controller = new CsrfController();

    @Test
    void getCsrfTokenShouldReturnTokenAndHeaderName() {
        CsrfToken csrfToken = mock(CsrfToken.class);

        when(csrfToken.getToken()).thenReturn("test-csrf-token");
        when(csrfToken.getHeaderName()).thenReturn("X-CSRF-TOKEN");

        Map<String, String> result = controller.getCsrfToken(csrfToken);

        assertEquals("test-csrf-token", result.get("token"));
        assertEquals("X-CSRF-TOKEN", result.get("headerName"));
    }
}

