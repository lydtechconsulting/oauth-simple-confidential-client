package dev.lydtech.security.simpleconfidentialclient.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@Slf4j
@RequestMapping("/")
public class MyController {

    @GetMapping(path = "/")
    public String index(Model model) {
        // Need to look up principal here. By including it as a method param, Spring will redirect to login (which isn't required for this endpoint)
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof AuthenticatedPrincipal user) {
            model.addAttribute("username", user.getName());
        }
        return "public";
    }

    @GetMapping(path = "/users")
    public String users(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        return "users";
    }

    @GetMapping(path = "/admin")
    public String admin(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        return "admin";
    }
}