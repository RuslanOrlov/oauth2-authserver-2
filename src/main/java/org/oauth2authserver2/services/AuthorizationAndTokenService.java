package org.oauth2authserver2.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Slf4j
@Service
public class AuthorizationAndTokenService {

    //private final RegisteredClientRepository registeredClientRepository;
    private final JdbcTemplate jdbcTemplate;
    private final JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper authorizationRowMapper;

    public AuthorizationAndTokenService(
            RegisteredClientRepository registeredClientRepository,
            JdbcTemplate jdbcTemplate) {
        //this.registeredClientRepository = registeredClientRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.authorizationRowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
    }

    public List<OAuth2Authorization> getUserAuthorizations(String principalName) {

        String sql = "SELECT * FROM oauth2_authorization WHERE principal_name = ?";
        List<OAuth2Authorization> authorizations =
                jdbcTemplate.query(sql, authorizationRowMapper, principalName);

        return authorizations;
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
