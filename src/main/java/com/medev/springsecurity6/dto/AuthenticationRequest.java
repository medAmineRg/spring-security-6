package com.medev.springsecurity6.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationRequest {

    private Long id;
    private String email;
    private String username;
    private String password;
}
