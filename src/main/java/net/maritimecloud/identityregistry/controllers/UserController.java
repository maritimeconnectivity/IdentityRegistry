/* Copyright 2015 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimecloud.identityregistry.controllers;

import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.User;
import net.maritimecloud.identityregistry.services.UserService;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"admin", "oidc", "x509"})
public class UserController {
    private UserService userService;

    @Autowired
    public void setUserService(UserService organizationService) {
        this.userService = organizationService;
    }

    /**
     * Creates a new User
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/user",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> createUser(HttpServletRequest request, @RequestBody User input) {
        User newUser = this.userService.saveUser(input);
        return new ResponseEntity<User>(newUser, HttpStatus.OK);
    }

    /**
     * Returns info about the user identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/user/{userId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getUser(HttpServletRequest request, @PathVariable Long userId) {
        User user = this.userService.getUserById(userId);
        return new ResponseEntity<User>(user, HttpStatus.OK);
    }

    /**
     * Updates a User
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/user/{userId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable Long userId, @RequestBody User input) {
        User user = this.userService.getUserById(userId);
        if (user != null && user.getId() == input.getId()) {
            input.copyTo(user);
            this.userService.saveUser(user);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    /**
     * Deletes a User
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/user/{userId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable Long userId) {
        User user = this.userService.getUserById(userId);
        if (user != null) {
            this.userService.deleteUser(userId);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

}

