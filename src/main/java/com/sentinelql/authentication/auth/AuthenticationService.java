package com.sentinelql.authentication.auth;

import com.sentinelql.authentication.user.User;
import com.sentinelql.authentication.user.UserRepository;
import com.sentinelql.authentication.user.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    public String register(RegistrationRequest request) {
        // check if user exists
        boolean userExists = userRepository.findByEmail(request.getEmail()).isPresent();
        if (userExists) {
            throw new IllegalStateException("email already taken");
        }

        // transform request to user
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(request.getPassword())
                .role(UserRole.USER)
                .build();

        // save user
        userRepository.save(user);

        // return success or failure
        return "User created successfully";
    }
}
