package org.oauth2authserver2.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class CheckConsentService {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public Boolean isConsentRemoved(String principalName) {
        String clientId = Objects.requireNonNull(registeredClientRepository.findByClientId("my-client-id")).getId();
        OAuth2AuthorizationConsent consent = authorizationConsentService.findById(clientId, principalName);

        log.info("==================================================");
        log.info("===            CheckConsentService             ===");
        log.info("=== clientId                                   === {}", clientId);
        log.info("=== principalName                              === {}", principalName);
        log.info("=== consent                                    === {}", consent);
        log.info("=== consent == null                            === {}", consent == null);
        log.info("==================================================");

        return consent == null;
    }

}
