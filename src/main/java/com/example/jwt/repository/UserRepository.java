package com.example.jwt.repository;

import com.example.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


// CRUD 함수를 JpaRepository가 가지고 있다.
// @Repository라는 annotation이 없어도 IoC가 된다.
// JpaRepository를 상속했기 때문에
public interface UserRepository extends JpaRepository<User, Long> {
    // findBy는 규칙=>Username문법
    // select * from USER where username=?
    public User findByUsername(String username);    // JPA Query Method
}
