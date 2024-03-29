package com.sentinelql.authentication.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    //SDP
    Optional<User> findByEmail(String email);
}
