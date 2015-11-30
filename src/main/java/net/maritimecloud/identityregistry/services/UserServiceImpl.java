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
package net.maritimecloud.identityregistry.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.User;
import net.maritimecloud.identityregistry.repositories.UserRepository;

@Service
public class UserServiceImpl implements UserService {
    private UserRepository UserRepository;

    @Autowired
    public void setUserRepository(UserRepository UserRepository) {
        this.UserRepository = UserRepository;
    }

    @Override
    public Iterable<User> listAllUsers() {
        return UserRepository.findAll();
    }

    @Override
    public User getUserById(Long id) {
        return UserRepository.findOne(id);
    }

    @Override
    public User saveUser(User user) {
        return UserRepository.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        UserRepository.delete(id);
    }

    @Override
    public List<User> listOrgUsers(int orgId) {
        return UserRepository.findByidOrganization(orgId);
    }
}

