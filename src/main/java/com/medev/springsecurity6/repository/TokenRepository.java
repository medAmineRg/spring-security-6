package com.medev.springsecurity6.repository;

import com.medev.springsecurity6.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query("""
    select t from Token t inner join User u
    on t.user.id = u.id
    where u.id = :userId and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidToken(Long userId);
    Optional<Token> findByJwtToken(String jwtToken);
}
