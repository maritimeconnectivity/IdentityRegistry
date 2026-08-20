/*
 * Copyright 2026 Maritime Connectivity Platform Consortium
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
package net.maritimeconnectivity.identityregistry.services;

import net.maritimeconnectivity.identityregistry.model.database.TimestampModel;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.repository.CrudRepository;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// Regression test for the inverted sanitization condition fixed in commit "Fix inverted sanitization logic":
// BaseServiceImpl.filterResult(Page) used to only sanitize *empty* pages (!data.hasContent()) instead of
// non-empty ones, so pages with content were returned to unauthorized callers without stripping sensitive fields.
class BaseServiceImplTest {

    private static class DummyEntity extends TimestampModel {
        private boolean cleared = false;

        @Override
        public boolean hasSensitiveFields() {
            return true;
        }

        @Override
        public void clearSensitiveFields() {
            cleared = true;
        }

        boolean isCleared() {
            return cleared;
        }
    }

    private static class DummyService extends BaseServiceImpl<DummyEntity> {
        @Override
        public CrudRepository<DummyEntity, Long> getRepository() {
            return null;
        }
    }

    @Test
    void filterResultSanitizesNonEmptyPageWhenUserIsUnauthorized() {
        DummyService service = new DummyService();
        AccessControlUtil accessControlUtil = mock(AccessControlUtil.class);
        when(accessControlUtil.hasAnyRoles(anyList())).thenReturn(false);
        service.setAccessControlUtil(accessControlUtil);

        DummyEntity entity = new DummyEntity();
        Page<DummyEntity> page = new PageImpl<>(List.of(entity));

        Page<DummyEntity> result = service.filterResult(page);

        assertTrue(result.hasContent());
        assertTrue(entity.isCleared(),
                "Sensitive fields should be cleared for a non-empty page when the caller is unauthorized");
    }

    @Test
    void filterResultLeavesNonEmptyPageUntouchedWhenUserIsAuthorized() {
        DummyService service = new DummyService();
        AccessControlUtil accessControlUtil = mock(AccessControlUtil.class);
        when(accessControlUtil.hasAnyRoles(anyList())).thenReturn(true);
        service.setAccessControlUtil(accessControlUtil);

        DummyEntity entity = new DummyEntity();
        Page<DummyEntity> page = new PageImpl<>(List.of(entity));

        service.filterResult(page);

        assertFalse(entity.isCleared(), "Sensitive fields should not be cleared for an authorized caller");
    }

    @Test
    void filterResultLeavesEmptyPageUntouched() {
        DummyService service = new DummyService();
        AccessControlUtil accessControlUtil = mock(AccessControlUtil.class);
        service.setAccessControlUtil(accessControlUtil);

        Page<DummyEntity> emptyPage = new PageImpl<>(Collections.emptyList());

        Page<DummyEntity> result = service.filterResult(emptyPage);

        assertFalse(result.hasContent());
    }
}
