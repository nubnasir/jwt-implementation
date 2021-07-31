package com.test.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/home")
    public String home(){
        return "Home page";
    }
    @GetMapping("/admin")
    public String admin(){
        return "Admin page";
    }
}
