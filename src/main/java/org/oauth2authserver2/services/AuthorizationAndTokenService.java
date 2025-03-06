package org.oauth2authserver2.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationAndTokenService {

    private final OAuth2AuthorizationService authorizationService;

    public List<OAuth2Authorization> getUserAuthorizations(String principalName) {
        Map<String, OAuth2Authorization> authorizations;
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

    public void revokeToken(String token, String tokenTypeHint) {
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
    }

}
