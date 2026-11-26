package com.authcore.auth.user.account;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserRequest {
    /** Left out: keep it. */
    @Pattern(regexp = "(?s).*\\S.*", message = "must not be blank")
    @Size(max = 100)
    private String firstName;

    /** Left out: keep it. Empty: remove it. */
    @Size(max = 100)
    private String lastName;
}
