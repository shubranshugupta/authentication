package com.portfoliopro.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {
	// todo: add cache functionality to reduce the number of database calls
	// todo: use proper http code for each exception
	// todo verification and password reset service are same and can be combined or
	// refactored
	// todo: need to solve verification email error
	// InsufficientAuthenticationException
	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
