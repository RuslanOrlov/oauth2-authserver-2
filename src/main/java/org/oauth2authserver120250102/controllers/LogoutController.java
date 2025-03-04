package org.oauth2authserver120250102.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.oauth2authserver120250102.services.AuthorizationAndTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.*;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LogoutController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationAndTokenService authorizationAndTokenService;

    @GetMapping("/oauth2/logout")
    public String logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            @RequestParam(name = "post_logout_redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "token", required = false) String accessToken
    )  {

        log.info("=== Выход из системы (сервер авторизации)      ===");

        String clientId = Objects.requireNonNull(registeredClientRepository.findByClientId("my-client-id")).getId();

        log.info("=== clientId                                   === {}", clientId);
        log.info("=== principalName                              === {}", authentication.getName());
        log.info("==================================================");

        // Очистка согласия клиента
        OAuth2AuthorizationConsent consent = authorizationConsentService.findById(
                clientId, authentication.getName()
        );
        if (consent != null) {
            log.info("=== consent (до удаления)                      === {}",
                    authorizationConsentService.findById(clientId, authentication.getName()));

            authorizationConsentService.remove(consent);

            log.info("=== Согласие клиента удалено                   ===");

            log.info("=== consent (после удаления)                   === {}",
                    authorizationConsentService.findById(clientId, authentication.getName()));

        } else {
            log.info("=== Согласие клиента не найдено                ===");
        }
        log.info("==================================================");

        List<OAuth2Authorization> authorizations =
                authorizationAndTokenService.getUserAuthorizations(authentication.getName());
        log.info("=== List of authorizations (до удаления)       === {}", authorizations);

        // Вариант 1 - Очистка ВСЕХ авторизаций текущего аутентифицированного пользователя
        if (authorizations != null && !authorizations.isEmpty()) {
            for (OAuth2Authorization authorization : authorizations) {

                String token = authorization.getAccessToken().getToken().getTokenValue();

                log.info("=== authorization (до удаления)                === {}",
                        authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN));

                log.info("==================================================");
                log.info("=== AccessToken (токен из авторизации)         === {}", token);
                log.info("=== AccessToken (токен из параметра метода)    === {}", accessToken);
                log.info("=== AccessToken (токены равны друг другу)      === {}", accessToken.equals(token));
                log.info("==================================================");

                authorizationService.remove(authorization);
                log.info("=== Авторизация удалена                        ===");

                log.info("=== List of authorizations (после удаления)    === {}",
                        authorizationAndTokenService.getUserAuthorizations(authentication.getName()));
                log.info("=== authorization (после удаления)             === {}",
                        authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN));

                log.info("=== AccessToken (статус токена до отзыва)      === {}", authorization.getAccessToken().isInvalidated());
                authorizationAndTokenService.revokeToken(token, "access_token");
                log.info("=== AccessToken (статус токена после отзыва)   === {}", authorization.getAccessToken().isInvalidated());
            }
        } else {
            log.info("=== Авторизации не найдены                     ===");
        }

        // Вариант 2 - Очистка ОДНОЙ авторизации текущего аутентифицированного пользователя
        /*if (accessToken != null) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    accessToken, OAuth2TokenType.ACCESS_TOKEN
            );
            if (authorization != null) {
                log.info("=== authorization (до удаления)                === {}",
                        authorizationService.findByToken(
                                accessToken, OAuth2TokenType.ACCESS_TOKEN
                        ));

                log.info("=== AccessToken (токен из авторизации)         === {}", authorization.getAccessToken().getToken().getTokenValue());
                log.info("=== AccessToken (токен из параметра метода)    === {}", accessToken);
                log.info("=== AccessToken (токены равны друг другу)      === {}", accessToken.equals(authorization.getAccessToken().getToken().getTokenValue()));
                log.info("=== AccessToken (статус токена до отзыва)      === {}", authorization.getAccessToken().isInvalidated());

                authorizationService.remove(authorization);

                log.info("=== Авторизация удалена                        ===");

                log.info("=== List of authorizations (после удаления)    === {}",
                        authorizationAndTokenService.getUserAuthorizations(authentication.getName()));

                log.info("=== authorization (после удаления)             === {}",
                        authorizationService.findByToken(
                                accessToken, OAuth2TokenType.ACCESS_TOKEN
                        ));

                authorizationAndTokenService.revokeToken(accessToken, "access_token");
                log.info("=== AccessToken (статус токена после отзыва)   === {}", authorization.getAccessToken().isInvalidated());

            } else {
                log.info("=== Авторизация не найдена                     ===");
            }
        }*/

        log.info("==================================================");

        // Очистка сессии
        SecurityContextHolder.clearContext();
        log.info("=== Контекст безопасности очищен               ===");
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        log.info("=== HTTP сессия инвалидирована                 ===");

        // Перенаправление на страницу входа
        return "redirect:" + redirectUri; /*request.getParameter("post_logout_redirect_uri");*/
    }

    /*private List<OAuth2Authorization> getUserAuthorizations(String principalName) {
        Map<String, OAuth2Authorization> authorizations = new HashMap<>();
        try {
            Field authorizationsField = InMemoryOAuth2AuthorizationService.class.getDeclaredField("authorizations");
            authorizationsField.setAccessible(true);
            authorizations = (Map<String, OAuth2Authorization>) authorizationsField.get(authorizationService);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            // Если что-то пошло не так при получении доступа к полю - выбрасываем исключение
            throw new RuntimeException("Failed to access authorizations map", e);
        }
        return authorizations.values()
                .stream()
                .filter(authorization -> authorization.getPrincipalName().equals(principalName))
                .toList();
    }

    private void revokeToken(String token, String tokenTypeHint) {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("my-client-id", "secret"); // Учетные данные клиента
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);
        body.add("token_type_hint", tokenTypeHint);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://authserver:9000/oauth2/revoke", request, String.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            log.info("=== AccessToken (Токен успешно отозван)        ===");
        } else {
            log.error("=== AccessToken (Ошибка при отзыве токена)     === {}", response.getBody());
        }
    }*/

}
