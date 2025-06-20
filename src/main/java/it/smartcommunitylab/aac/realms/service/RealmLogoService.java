/**
 * Copyright 2025 the original author or authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.smartcommunitylab.aac.realms.service;

import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.common.NoSuchRealmException;
import it.smartcommunitylab.aac.realms.model.RealmLogo;
import it.smartcommunitylab.aac.realms.persistence.RealmEntity;
import it.smartcommunitylab.aac.realms.persistence.RealmEntityRepository;
import it.smartcommunitylab.aac.realms.persistence.RealmLogoEntity;
import it.smartcommunitylab.aac.realms.persistence.RealmLogoEntityRepository;
import java.io.IOException;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Service
@Transactional
public class RealmLogoService {

    public static final int MAX_LOGO_SIZE = 256 * 1024; // 256 KB

    private final RealmLogoEntityRepository logoRepository;
    private final RealmEntityRepository realmRepository;

    public RealmLogoService(RealmLogoEntityRepository logoRepository, RealmEntityRepository realmRepository) {
        Assert.notNull(realmRepository, "realm repository is mandatory");
        Assert.notNull(logoRepository, "logo repository is mandatory");

        this.realmRepository = realmRepository;
        this.logoRepository = logoRepository;
    }

    public RealmLogo findLogo(String slug) {
        if (!StringUtils.hasText(slug)) {
            return null;
        }

        if (SystemKeys.REALM_SYSTEM.equals(slug)) {
            return null; // system realm does not have a logo
        }
        RealmLogoEntity logo = logoRepository.findByRealm(slug);
        if (logo == null) {
            return null;
        }

        return to(logo);
    }

    public RealmLogo getLogo(String slug) throws NoSuchRealmException {
        RealmLogo logo = findLogo(slug);
        if (logo == null) {
            throw new NoSuchRealmException();
        }

        return logo;
    }

    public void deleteLogo(String slug) {
        RealmLogoEntity logo = logoRepository.findByRealm(slug);
        if (logo != null) {
            logoRepository.delete(logo);
        }
    }

    public RealmLogo uploadLogo(String realm, String fileName, String mimeType, byte[] data)
        throws NoSuchRealmException, IOException {
        Assert.hasText(realm, "realm slug is mandatory");
        Assert.isTrue(StringUtils.hasText(fileName), "file name is mandatory");
        Assert.isTrue(StringUtils.hasText(mimeType), "mime type is mandatory");

        RealmEntity r = realmRepository.findBySlug(realm);
        if (r == null) {
            throw new NoSuchRealmException();
        }

        RealmLogoEntity logo = logoRepository.findByRealm(realm);
        if (logo == null) {
            logo = new RealmLogoEntity();
            logo.setRealm(realm);
            logo.setId(UUID.randomUUID().toString());
        }

        logo.setFileName(fileName);
        logo.setMimeType(mimeType);
        logo.setImage(data);

        logo = logoRepository.saveAndFlush(logo);

        return to(logo);
    }

    private RealmLogo to(RealmLogoEntity entity) {
        if (entity == null) {
            return null;
        }

        RealmLogo logo = new RealmLogo();
        logo.setId(entity.getId());
        logo.setRealm(entity.getRealm());
        logo.setFileName(entity.getFileName());
        logo.setMimeType(entity.getMimeType());
        logo.setImage(entity.getImage());

        return logo;
    }
}
