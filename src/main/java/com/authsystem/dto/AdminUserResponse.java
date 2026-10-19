
package com.authsystem.dto;

public record AdminUserResponse(
        Long id,
        String name,
        String email,
        String role
) {
}
