package com.portfoliopro.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.dto.request.DeleteAccountRequest;
import com.portfoliopro.auth.dto.request.UpdateUserRequest;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.response.UserResposne;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.DeleteAccountOtp;
import com.portfoliopro.auth.event.DeleteAccountEvent;
import com.portfoliopro.auth.repository.UserRepository;
import com.portfoliopro.auth.service.token.TokenType;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
        private final UserRepository userRepository;
        private final JwtService jwtService;
        private final TokenServiceFacade tokenService;
        private final ApplicationEventPublisher eventPublisher;

        @Value("${auth.base-url}")
        private String APP_URL;

        public UserResposne getUserInfo(String token) {
                String email = jwtService.getEmailFromToken(token);
                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException(email + " user not exists."));

                return UserResposne.builder()
                                .email(user.getEmail())
                                .firstName(user.getFirstName())
                                .lastName(user.getLastName())
                                .build();
        }

        public MsgResponse updateUserInfo(String token, UpdateUserRequest newInfo) {
                String email = jwtService.getEmailFromToken(token);
                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException(email + " user not exists."));

                user.setFirstName(newInfo.getFirstName());
                user.setLastName(newInfo.getLastName());

                userRepository.save(user);

                return MsgResponse.builder()
                                .msg("User info updated successfully.")
                                .build();
        }

        public MsgResponse deleteUser(String token, DeleteAccountRequest request) {
                String email = jwtService.getEmailFromToken(token);
                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException(email + " user not exists."));

                if (request == null) {
                        DeleteAccountOtp otp = (DeleteAccountOtp) tokenService.createToken(user,
                                        TokenType.DELETE_ACCOUNT_TOKEN);

                        TokenEmailDTO emailDTO = TokenEmailDTO.builder()
                                        .email(user.getEmail())
                                        .firstName(user.getFirstName())
                                        .lastName(user.getLastName())
                                        .token(otp.getToken())
                                        .baseUrl(APP_URL)
                                        .build();

                        eventPublisher.publishEvent(new DeleteAccountEvent(user, emailDTO));

                        return MsgResponse.builder()
                                        .msg("Delete account email sent.")
                                        .build();
                }

                tokenService.verifyToken(user, String.valueOf(request.getOtp()), TokenType.DELETE_ACCOUNT_TOKEN);
                userRepository.delete(user);

                return MsgResponse.builder()
                                .msg("User deleted successfully.")
                                .build();
        }
}
