
package com.authsystem.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.authsystem.entity.PasswordResetOtp;
import com.authsystem.entity.User;

import jakarta.persistence.LockModeType;

public interface PasswordResetOtpRepository
        extends JpaRepository<PasswordResetOtp, Long> {

    List<PasswordResetOtp> findByUserAndUsedFalse(User user);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT otp
            FROM PasswordResetOtp otp
            WHERE otp.user = :user
              AND otp.used = false
            ORDER BY otp.id DESC
            """)
    List<PasswordResetOtp> findUnusedOtpsForUpdate(
            @Param("user") User user);

    Optional<PasswordResetOtp>
            findTopByUserAndUsedFalseOrderByIdDesc(User user);
}
