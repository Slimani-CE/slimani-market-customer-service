package com.slimanice.customerfrontthymeleafapp.web;

import com.slimanice.customerfrontthymeleafapp.entity.Customer;
import com.slimanice.customerfrontthymeleafapp.model.Product;
import com.slimanice.customerfrontthymeleafapp.repository.CustomerRepository;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;

import java.lang.reflect.Type;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
// A controller that will handle the view
// This is a server-side MVC Architecture
public class CustomerController {
    private CustomerRepository customerRepository;
    private ClientRegistrationRepository clientRegistrationRepository;

    public CustomerController(CustomerRepository customerRepository, ClientRegistrationRepository clientRegistrationRepository) {
        this.customerRepository = customerRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @GetMapping("/customers")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String customers(Model model, Principal principal) {
        System.out.println(principal);
        List<Customer> customerList = customerRepository.findAll();
        model.addAttribute("customers", customerList);
        return "customers";
    }

    @GetMapping("/products")
    public String products(Model model) {
        // The following two lines are equivalent to the injection of Authentication in the products parameters
        // But this will help if we're in other destination in which we can't do injection
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        DefaultOidcUser oidcUser = (DefaultOidcUser) oAuth2AuthenticationToken.getPrincipal();
        String jwtTokenValue = oidcUser.getIdToken().getTokenValue();
        RestClient restClient = RestClient.create("http://localhost:8098");
        List<Product> products = restClient.get()
                .uri("/products")
                .headers(httpHeaders -> httpHeaders.set(HttpHeaders.AUTHORIZATION, "Bearer " + jwtTokenValue))
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
        model.addAttribute("products", products);
        return "products";
    }

    @GetMapping("/auth")
    // To return the authentication object in JSON format
    @ResponseBody
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    @GetMapping("/notAuthorized")
    public String notAutorized() {
        return "notAuthorized";
    }

    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model) {
        String authorizationRequestBaseUri = "oauth2/authorization";
        Map<String, String> oauth2AuthenticationUrls = new HashMap<>();
        Iterable<ClientRegistration> clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        clientRegistrations.forEach(clientRegistration -> {
            oauth2AuthenticationUrls.put(clientRegistration.getClientName(), authorizationRequestBaseUri + "/" + clientRegistration.getRegistrationId());
        });
        model.addAttribute("urls", oauth2AuthenticationUrls);
        return "oauth2Login";
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }
}
