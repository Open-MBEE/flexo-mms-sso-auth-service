package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.entity.ApiKey;
import org.openmbee.flexo.mms.sso.service.ApiKeyService;
import org.openmbee.flexo.mms.sso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;

@Controller
public class MainController {

    private final UserService userService;
    private final ApiKeyService apiKeyService;

    @Autowired
    public MainController(UserService userService, ApiKeyService apiKeyService) {
        this.userService = userService;
        this.apiKeyService = apiKeyService;
    }

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/user")
    public String user(Authentication authentication, Model model) {
        Map<String, Object> userDetails = userService.getUserDetails(authentication);
        model.addAttribute("userDetails", userDetails);
        return "user";
    }

    @GetMapping("/api/userinfo")
    @ResponseBody
    public Map<String, Object> userInfo(Authentication authentication) {
        return userService.getUserDetails(authentication);
    }
}