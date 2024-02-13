package com.medev.springsecurity6.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/private")
public class PrivateController {

    @GetMapping
    public String privateMethod() {
        return "Hello from the private method inside the private controller";
    }
}
