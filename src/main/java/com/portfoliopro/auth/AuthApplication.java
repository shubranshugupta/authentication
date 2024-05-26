package com.portfoliopro.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {
	// todo: use proper http code for each exception
	// todo: need to handle email body cretion in a better way in event listner
	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
