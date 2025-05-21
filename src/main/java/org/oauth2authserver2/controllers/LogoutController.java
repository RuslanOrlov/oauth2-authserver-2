package org.oauth2authserver2.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.oauth2authserver2.services.LogoutService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class LogoutController {

    private final LogoutService logoutService;

    @GetMapping("/oauth2/logout")
    public String logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            @RequestParam(name = "post_logout_redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "token", required = false) String accessToken
    )  {
        // Выход из системы (сервер авторизации)
        logoutService.logout(request, response, authentication, accessToken);

        // Перенаправление на страницу приложения клиента после выхода из системы
        return "redirect:" + redirectUri; /*request.getParameter("post_logout_redirect_uri");*/
    }
}
