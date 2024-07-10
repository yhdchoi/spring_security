package com.yhdc.security.repository;

import com.yhdc.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    // For security filter
    Optional<User> findByEmail(String email);

}
