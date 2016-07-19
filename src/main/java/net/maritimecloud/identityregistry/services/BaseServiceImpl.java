/* Copyright 2016 Danish Maritime Authority.
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

import com.google.common.collect.Lists;
import net.maritimecloud.identityregistry.model.database.TimestampModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

public abstract class BaseServiceImpl<T extends TimestampModel> implements BaseService<T> {

    protected T filterResult(T data) {
        if (data != null && data.hasSensitiveFields()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean authorized = false;
            for (GrantedAuthority authority : auth.getAuthorities()) {
                String role = authority.getAuthority();
                if ("ROLE_SITE_ADMIN".equals(role) || "ROLE_ORG_ADMIN".equals(role)) {
                    authorized = true;
                    break;
                }
            }
            // If not authorized to see all we clean the object for sensitive data.
            if (!authorized) {
                data.clearSensitiveFields();
            }
        }
        return data;
    }

    protected List<T> filterResult(List<T> data) {
        if (data != null && !data.isEmpty() && data.get(0).hasSensitiveFields()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean authorized = false;
            for (GrantedAuthority authority : auth.getAuthorities()) {
                String role = authority.getAuthority();
                if ("ROLE_SITE_ADMIN".equals(role) || "ROLE_ORG_ADMIN".equals(role)) {
                    authorized = true;
                    break;
                }
            }
            // If not authorized to see all we clean the object for sensitive data.
            if (!authorized) {
                for (T entity : data) {
                    entity.clearSensitiveFields();
                }
            }
        }
        return data;
    }

    public List<T> listAll() {
        return Lists.newArrayList(getRepository().findAll());
    }

    public T getById(Long id) {
        T ret = getRepository().findOne(id);
        ret = this.filterResult(ret);
        return ret;
    }

    public T save(T service) {
        return getRepository().save(service);
    }

    public void delete(Long id) {
        getRepository().delete(id);
    }
}