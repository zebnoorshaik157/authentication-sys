
package com.authsystem.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TestControllerTest {

    private final TestController controller = new TestController();

    @Test
    void helloShouldReturnHelloMessage() {
        assertEquals(
                "Hello from authentication system",
                controller.hello());
    }
}
