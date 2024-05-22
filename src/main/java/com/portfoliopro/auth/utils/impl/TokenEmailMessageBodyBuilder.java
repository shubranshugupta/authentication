package com.portfoliopro.auth.utils.impl;

import java.util.Map;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.utils.EmailMessageBodyBuilder;

public class TokenEmailMessageBodyBuilder implements EmailMessageBodyBuilder<Map<String, String>> {
    private final TemplateEngine templateEngine = new TemplateEngine();
    private final Context context = new Context();
    private String templateName;

    public TokenEmailMessageBodyBuilder(String templateName) {
        this.templateName = templateName;
    }

    @Override
    public String getMessage(Map<String, String> data) {

        for (Map.Entry<String, String> entry : data.entrySet()) {
            context.setVariable(entry.getKey(), entry.getValue());
        }

        return templateEngine.process(templateName, context);
    }

}
