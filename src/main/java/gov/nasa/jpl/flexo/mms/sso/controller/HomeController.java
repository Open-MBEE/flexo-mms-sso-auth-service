package org.openmbee.flexo.mms.sso.controller;

import org.openmbee.flexo.mms.sso.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class HomeController {

    private final UserService userService;

    @Autowired
    public HomeController(UserService userService) {
        this.userService = userService;
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
