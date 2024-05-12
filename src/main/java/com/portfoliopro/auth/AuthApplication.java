package com.portfoliopro.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {
	// todo: add cache functionality to reduce the number of database calls
	// todo: exception are complex and need to be simplified
	// todo: use proper http code for each exception
	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
