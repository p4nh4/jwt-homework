package com.spring.springbootjwt.repository;

import com.spring.springbootjwt.model.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Repository
@Mapper
public interface UserRepo {
    @Select("select * from users")
    List<User> allUser();
    @Select("select * from users where username like #{username}")
    User findUserByName(String username);
}
