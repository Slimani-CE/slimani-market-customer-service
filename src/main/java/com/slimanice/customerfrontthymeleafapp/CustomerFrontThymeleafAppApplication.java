package com.slimanice.customerfrontthymeleafapp;

import com.slimanice.customerfrontthymeleafapp.entity.Customer;
import com.slimanice.customerfrontthymeleafapp.repository.CustomerRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CustomerFrontThymeleafAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(CustomerFrontThymeleafAppApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(CustomerRepository customerRepository) {
		return args -> {
			customerRepository.save(new Customer(null, "Mustapha", "mustapha@mail.com"));
			customerRepository.save(new Customer(null, "Mohammed", "mohamed@mail.com"));
			customerRepository.save(new Customer(null, "Imane", "imane@mail.com"));
		};
	}

}
