package org.oauth2authserver2.dev;

import lombok.RequiredArgsConstructor;
import org.oauth2authserver2.models.MyUser;
import org.oauth2authserver2.repositories.MyUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements CommandLineRunner {

    private final MyUserRepository repo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        repo.save(MyUser.builder()
                .username("user_1")
                .password(passwordEncoder.encode("password"))
                .role("SCOPE_WRITE")
                .build());
        repo.save(MyUser.builder()
                .username("user_2")
                .password(passwordEncoder.encode("password"))
                .role("SCOPE_DELETE")
                .build());
    }
}
