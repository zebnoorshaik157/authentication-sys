
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HomeControllerTest {

    private final HomeController controller = new HomeController();

    @Test
    void homeShouldReturnWelcomeMessage() {
        assertEquals(
                "Welcome to Authentication System!",
                controller.home());
    }
}
