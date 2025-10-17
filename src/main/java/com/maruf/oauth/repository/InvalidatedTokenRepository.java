package com.maruf.oauth.repository;

import com.maruf.oauth.entity.InvalidatedToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface InvalidatedTokenRepository extends MongoRepository<InvalidatedToken, String> {
    
    boolean existsByToken(String token);
}