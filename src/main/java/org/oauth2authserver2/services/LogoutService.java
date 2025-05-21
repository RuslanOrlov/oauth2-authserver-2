package org.oauth2authserver2.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationAndTokenService authorizationAndTokenService;

    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication,
                       String accessToken
    ) {
        log.info("==================================================");
        log.info("Выход из системы (сервер авторизации):");
        String clientId = Objects.requireNonNull(
                registeredClientRepository.findByClientId("my-client-id")).getId();

        // Получение согласия пользователя
        OAuth2AuthorizationConsent consent = authorizationConsentService.findById(
                clientId, authentication.getName()
        );
        // Очистка согласия пользователя
        if (consent != null) {
            authorizationConsentService.remove(consent);
            log.info("Согласие удалено!");
        } else {
            log.info("Согласие не найдено!");
        }

        // Получение всех авторизаций текущего аутентифицированного пользователя
        List<OAuth2Authorization> authorizations =
                authorizationAndTokenService.getUserAuthorizations(authentication.getName());
        // Вариант 1 - Очистка ВСЕХ авторизаций текущего аутентифицированного пользователя
        if (authorizations != null && !authorizations.isEmpty()) {
            for (OAuth2Authorization authorization : authorizations) {
                String token = authorization.getAccessToken().getToken().getTokenValue();
                authorizationService.remove(authorization);
                authorizationAndTokenService.revokeToken(token, "access_token");
                log.info("Авторизация удалена!");
            }
        } else {
            log.info("Авторизации не найдены!");
        }

        // Вариант 2 - Очистка ОДНОЙ авторизации текущего аутентифицированного пользователя
        /*if (accessToken != null) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    accessToken, OAuth2TokenType.ACCESS_TOKEN
            );
            if (authorization != null) {
                authorizationService.remove(authorization);
                authorizationAndTokenService.revokeToken(accessToken, "access_token");
                log.info("Авторизация удалена!");
            } else {
                log.info("Авторизация не найдена!");
            }
        }*/

        // Очистка сессии
        SecurityContextHolder.clearContext();
        log.info("Контекст безопасности очищен");
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        log.info("HTTP сессия инвалидирована");
        log.info("==================================================");
    }
}
