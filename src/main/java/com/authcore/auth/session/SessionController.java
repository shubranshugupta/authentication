package com.authcore.auth.session;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.MsgResponse;
import com.authcore.auth.security.UserPrincipal;

import lombok.RequiredArgsConstructor;

/** Where the logged-in user is logged in. */
@RestController
@RequestMapping("/api/v1/users/me/sessions")
@RequiredArgsConstructor
public class SessionController {
    private final SessionService sessions;

    @GetMapping
    public ResponseEntity<List<SessionResponse>> listSessions(@AuthenticationPrincipal UserPrincipal me) {
        return ResponseEntity.ok(sessions.list(me.id(), me.sessionId()));
    }

    /** Logs out everywhere, here too. */
    @DeleteMapping
    public ResponseEntity<MsgResponse> endAllSessions(@AuthenticationPrincipal UserPrincipal me) {
        sessions.endAll(me.id());
        return message("Logged out of all devices.");
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<MsgResponse> endSession(@AuthenticationPrincipal UserPrincipal me, @PathVariable Long id) {
        sessions.end(me.id(), id);
        return message("Session ended.");
    }

    private static ResponseEntity<MsgResponse> message(String msg) {
        return ResponseEntity.ok(MsgResponse.builder().msg(msg).build());
    }
}
