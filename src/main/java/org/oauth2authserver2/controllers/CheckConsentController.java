package org.oauth2authserver2.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.oauth2authserver2.services.CheckConsentService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@Slf4j
@RestController
@RequiredArgsConstructor
public class CheckConsentController {

    private final CheckConsentService checkConsentService;

    @PostMapping("/oauth2/check-consent")
    public Boolean isConsentRemoved(
            @RequestBody String principalName,
            /*@RequestParam(value = "principalName", required = false) String principalName,*/
            @RequestHeader(value = "Authorization", required = false) String authHeader
    ) {
        log.info("==================================================");
        log.info("===          CheckConsentController            ===");
        log.info("=== principalName                              === {}", principalName);
        log.info("=== authHeader                                 === {}", authHeader);
        return checkConsentService.isConsentRemoved(principalName);
    }

}
