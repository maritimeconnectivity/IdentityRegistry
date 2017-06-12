/*
 * Copyright 2017 Danish Maritime Authority.
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

import net.maritimecloud.identityregistry.model.database.TimestampModel;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

@Transactional(readOnly = true)
public abstract class BaseServiceImpl<T extends TimestampModel> implements BaseService<T> {
    private static final Logger logger = LoggerFactory.getLogger(BaseServiceImpl.class);

    protected final List<String> authorizedRoles =  Arrays.asList("ORG_ADMIN", "SITE_ADMIN");

    @Autowired
    protected AccessControlUtil accessControlUtil;

    protected boolean isAuthorized() {
        return accessControlUtil.hasAnyRoles(authorizedRoles);
    }

    protected T filterResult(T data) {
        if (data != null && data.hasSensitiveFields()) {
            // If not authorized to see all we clean the object for sensitive data.
            if (!isAuthorized()) {
                logger.debug("Clearing Sensitive Fields");
                data.clearSensitiveFields();
            }
        }
        return data;
    }

    protected Page<T> filterResult(Page<T> data) {
        if (data != null && !data.hasContent()) {
            data = (Page<T>) this.filterIterable(data);
        }
        return data;
    }

    protected List<T> filterResult(List<T> data) {
        if (data != null && !data.isEmpty()) {
            data = (List<T>) this.filterIterable(data);
        }
        return data;
    }

    protected Iterable<T> filterIterable(Iterable<T> data) {
        // If not authorized to see all we clean the object for sensitive data.
        if (!isAuthorized()) {
            logger.debug("Clearing Sensitive Fields");
            for (T entity : data) {
                if (!entity.hasSensitiveFields()) {
                    break;
                }
                entity.clearSensitiveFields();
            }
        }
        return data;
    }

    public T getById(Long id) {
        T ret = getRepository().findOne(id);
        return filterResult(ret);
    }

    @Transactional
    public T save(T entity) {
        logger.debug("Just saved entity");
        return getRepository().save(entity);
    }

    @Transactional
    public void delete(Long id) {
        getRepository().delete(id);
    }
}