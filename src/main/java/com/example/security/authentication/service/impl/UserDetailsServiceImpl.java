/**
 * Created by Mohammad Khalid Hasan|| BJIT-R&D
 * Since: 4/24/2024
 * Version: 1.0
 */

package com.example.security.authentication.service.impl;

import com.example.security.common.model.User;
import com.example.security.common.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);


    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * A method to load user details by username.
     *
     * @param  username   the username to load the user details
     * @return            the user details for the provided username
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Entering in loadUserByUsername Method...");
        User user = userRepository.findByEmail(username)
                .orElseThrow(()->new UsernameNotFoundException("User Not Found"));
        logger.info("User found Successfully..!!!");
        return user;
    }
}
