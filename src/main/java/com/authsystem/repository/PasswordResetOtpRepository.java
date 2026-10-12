
package com.authsystem.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authsystem.entity.PasswordResetOtp;
import com.authsystem.entity.User;

public interface PasswordResetOtpRepository
        extends JpaRepository<PasswordResetOtp, Long> {

    List<PasswordResetOtp> findByUserAndUsedFalse(User user);

    Optional<PasswordResetOtp>
            findTopByUserAndUsedFalseOrderByIdDesc(User user);
}
