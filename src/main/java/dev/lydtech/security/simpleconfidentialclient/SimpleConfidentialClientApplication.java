package dev.lydtech.security.simpleconfidentialclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@SpringBootApplication
public class SimpleConfidentialClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(SimpleConfidentialClientApplication.class, args);
	}

}
