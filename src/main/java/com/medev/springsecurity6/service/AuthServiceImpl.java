package com.medev.springsecurity6.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medev.springsecurity6.dto.AuthenticationRequest;
import com.medev.springsecurity6.dto.AuthenticationResponse;
import com.medev.springsecurity6.enm.TokenType;
import com.medev.springsecurity6.entity.Token;
import com.medev.springsecurity6.entity.User;
import com.medev.springsecurity6.repository.TokenRepository;
import com.medev.springsecurity6.repository.UserRepository;
import com.medev.springsecurity6.utils.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    @Override
    public AuthenticationResponse register(AuthenticationRequest request) {
        var user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);

        var extraClaims = jwtUtil.generateClaims(user);
        var accessToken = jwtUtil.generateToken(extraClaims, user);
        var refreshToken = jwtUtil.generateRefreshToken(user);
        saveUserToken(accessToken, user);
        return AuthenticationResponse.builder()
                    .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
    @Override
    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findUserByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(""));

        revokeUserTokens(user);

        var extraClaims = jwtUtil.generateClaims(user);
        var accessToken = jwtUtil.generateToken(extraClaims, user);
        var refreshToken = jwtUtil.generateRefreshToken(user);
        saveUserToken(accessToken, user);
        return AuthenticationResponse
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtUtil.extractUsername(refreshToken);
        if (userEmail != null) {

            User user = userRepository.findUserByEmail(userEmail)
                    .orElseThrow(()-> new UsernameNotFoundException("User wasn't found!"));

            if (jwtUtil.isTokenValid(refreshToken, user)) {
                var extraClaims = jwtUtil.generateClaims(user);
                var accessToken = jwtUtil.generateToken(extraClaims, user);
                revokeUserTokens(user);
                saveUserToken(accessToken, user);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void saveUserToken(String token, User user) {
        var jwtToken = Token.builder()
                .jwtToken(token)
                .expired(false)
                .revoked(false)
                .user(user)
                .tokenType(TokenType.BEARER)
                .build();
        tokenRepository.save(jwtToken);
    }
    private void revokeUserTokens(User user) {
        List<Token> allGeneratedUserToken = tokenRepository.findAllValidToken(user.getId());

        if(!allGeneratedUserToken.isEmpty()) {
            allGeneratedUserToken.forEach(t -> {
                t.setExpired(true);
                t.setRevoked(true);
            });

            tokenRepository.saveAll(allGeneratedUserToken);
        }
    }
}
