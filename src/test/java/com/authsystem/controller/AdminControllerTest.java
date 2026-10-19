
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import com.authsystem.repository.UserRepository;

class AdminControllerTest {

    private final UserRepository userRepository =
            mock(UserRepository.class);

    private final AdminController controller =
            new AdminController(userRepository);

    @Test
    void adminDashboardShouldReturnWelcomeMessage() {
        assertEquals(
                "Welcome to the Admin Dashboard!",
                controller.adminDashboard());
    }

    @Test
    void getUsersShouldRejectNegativePage() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.getUsers(-1, 10, "id", "asc"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(userRepository);
    }

    @Test
    void getUsersShouldRejectInvalidPageSize() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.getUsers(0, 101, "id", "asc"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(userRepository);
    }

    @Test
    void getUsersShouldRejectInvalidSortField() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.getUsers(0, 10, "password", "asc"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(userRepository);
    }

    @Test
    void getUsersShouldRejectInvalidSortDirection() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.getUsers(0, 10, "id", "sideways"));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(userRepository);
    }
}
