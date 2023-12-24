package com.slimanice.customerfrontthymeleafapp.model;

import jakarta.persistence.Id;
import lombok.*;

@NoArgsConstructor @AllArgsConstructor @Getter @Setter @Builder
public class Product {
    @Id
    private String id;
    private String name;
    private double price;
    private int quantity;
}
