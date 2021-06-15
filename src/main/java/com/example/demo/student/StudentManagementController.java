package com.example.demo.student;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMINTRAINEE;
import static org.springframework.security.authorization.AuthorityReactiveAuthorizationManager.*;

@RestController
@RequestMapping("management/api/v1/students")

public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public void getStudents(){
        System.out.println("Get all");
    }
    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void addStudent(@RequestBody Student student){
        System.out.println("add");
    }
}
