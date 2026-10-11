package com.authsystem.repository;

import java.util.Optional;


import org.springframework.data.jpa.repository.JpaRepository;

import com.authsystem.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

}