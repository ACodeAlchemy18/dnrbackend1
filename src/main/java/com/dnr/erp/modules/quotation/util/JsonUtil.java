package com.dnr.erp.modules.quotation.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

public class JsonUtil {
    private static final ObjectMapper mapper = new ObjectMapper();

    public static JsonNode toJsonNode(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Invalid JSON", e);
        }
    }
}
