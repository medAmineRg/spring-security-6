package com.medev.springsecurity6.entity;


import com.medev.springsecurity6.enm.TokenType;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class Token {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String jwtToken;
    private boolean revoked;
    private boolean expired;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}
