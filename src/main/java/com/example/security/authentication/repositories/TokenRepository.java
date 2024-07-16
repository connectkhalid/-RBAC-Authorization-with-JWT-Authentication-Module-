package com.example.security.authentication.repositories;

import com.example.security.common.model.Token;
import com.example.security.common.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {


    @Query("""
select t from Token t inner join User u on t.user.id = u.id
where t.user.id = :userId
""")
    List<Token> findAllAccessTokensByUser(Integer userId);

    Boolean existsByAccessToken(String token);

    Integer findUserIdByAccessToken(String token);

    Boolean deleteAllByUserId(Integer userId);

    Optional<Token> findByUser(User user);
}