package com.appsdeveloperblog.ws.api.ResourceServer.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UsersController {
	
	@Autowired
	Environment env;

	@GetMapping("/status/check")
	public String status() {
		return "Working on port: " + env.getProperty("local.server.port");
	}

	@GetMapping("/status/check/unprotected")
	public String statusAuth() {
		return "This is unprotected api and working on port: " + env.getProperty("local.server.port");
	}	
//	
//	@PreAuthorize("hasAuthority('ROLE_developer') or #id == #jwt.subject") 
//	//@Secured("ROLE_developer")
//    @DeleteMapping(path = "/{id}")
//    public String deleteUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
//        return "Deleted user with id " + id + " and JWT subject " + jwt.getSubject();
//    }
//	
//
//	@PostAuthorize("returnObject.userId == #jwt.subject")
//    @GetMapping(path = "/{id}")
//    public UserRest getUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
//        return new UserRest("Sergey", "Kargopolov","5f3fb480-f86c-4514-8d23-ca88d66c6253");
//    }
//	
}
