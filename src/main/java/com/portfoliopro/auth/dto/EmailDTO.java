package com.portfoliopro.auth.dto;

import java.io.Serializable;
import java.util.Map;

public interface EmailDTO extends Serializable {
    Map<String, String> getAllData();
}
