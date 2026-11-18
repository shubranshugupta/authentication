package com.authcore.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class MailBody {
    private String to;
    private String subject;
    private String text;
}
