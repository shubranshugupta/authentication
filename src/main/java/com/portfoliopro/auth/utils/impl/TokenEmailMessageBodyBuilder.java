package com.portfoliopro.auth.utils.impl;

import java.util.Map;

import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.utils.EmailMessageBodyBuilder;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class TokenEmailMessageBodyBuilder implements EmailMessageBodyBuilder<Map<String, String>> {
    private final TemplateEngine templateEngine;
    private String templateName;

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public String getTemplateName() {
        return templateName;
    }

    @Override
    public String getMessage(Map<String, String> data) {
        Context context = new Context();

        for (Map.Entry<String, String> entry : data.entrySet()) {
            context.setVariable(entry.getKey(), entry.getValue());
        }

        if (templateName == null)
            throw new IllegalArgumentException("Template name is not set");

        return templateEngine.process(templateName, context);
    }

}
