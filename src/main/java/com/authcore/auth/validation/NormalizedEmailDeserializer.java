package com.authcore.auth.validation;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdScalarDeserializer;

/**
 * Normalizes an email while the JSON body is read, so validation sees the same value
 * that is stored. (@Email rejects the spaces that normalizing removes.)
 */
public class NormalizedEmailDeserializer extends StdScalarDeserializer<String> {
    public NormalizedEmailDeserializer() {
        super(String.class);
    }

    @Override
    public String deserialize(JsonParser parser, DeserializationContext context) {
        return EmailAddresses.normalize(context.readValue(parser, String.class));
    }
}
