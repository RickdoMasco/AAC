/*
 * Copyright 2023 the original author or authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.smartcommunitylab.aac.controller;

import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.config.ApplicationProperties;
import it.smartcommunitylab.aac.realms.RealmManager;
import it.smartcommunitylab.aac.realms.model.RealmLogo;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.activation.MimetypesFileTypeMap;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping
public class LogoController {

    @Autowired
    private ApplicationProperties appProps;

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    private RealmManager realmManager;

    private String logoEtagValue = null;
    private Map<String, String> realmLogoEtagValues = new HashMap<>();

    @RequestMapping(value = "/logo", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<InputStreamResource> logo() throws IOException {
        // read resource as is
        Resource resource = resourceLoader.getResource(appProps.getLogo());
        if (resource == null) {
            throw new IOException();
        }

        // guess mimeType
        String contentType = "image/png";
        String fileName = resource.getFilename();
        if (fileName != null) {
            MimetypesFileTypeMap fileTypeMap = new MimetypesFileTypeMap();
            contentType = fileTypeMap.getContentType(fileName);
        }

        if (logoEtagValue == null) {
            // read fully and build etag once, this can change only on restart
            logoEtagValue = computeWeakEtag(resource.getInputStream());
        }

        return ResponseEntity.ok()
            .contentLength(resource.contentLength())
            .contentType(MediaType.parseMediaType(contentType))
            .cacheControl(CacheControl.maxAge(3600, TimeUnit.SECONDS))
            .eTag(logoEtagValue)
            .body(new InputStreamResource(resource.getInputStream()));
        //        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }

    @RequestMapping(value = { "/-/{realm}/logo" }, method = RequestMethod.GET)
    public String realmLogo(@PathVariable @Valid @NotNull @Pattern(regexp = SystemKeys.SLUG_PATTERN) String realm)
        throws IOException {
        RealmLogo logo = realmManager.findLogo(realm);
        if (logo == null || logo.getImage() == null || logo.getImage().length == 0) {
            // no logo, return base
            return "redirect:/logo";
        }

        String fileName = logo.getFileName();

        String key = realm + "|" + fileName;
        String etag = realmLogoEtagValues.get(key);

        if (etag == null) {
            // read fully and build etag
            etag = computeWeakEtag(new ByteArrayInputStream(logo.getImage()));
            realmLogoEtagValues.put(key, etag);
        }

        return "redirect:/logo/" + etag.substring(2);
    }

    @RequestMapping(value = { "/logo/{etag}" }, method = RequestMethod.GET)
    public ResponseEntity<InputStreamResource> etagLogo(
        @PathVariable @Valid @NotNull @Pattern(regexp = SystemKeys.SLUG_PATTERN) String etag
    ) throws IOException {
        String key = realmLogoEtagValues
            .entrySet()
            .stream()
            .filter(e -> e.getValue().equals("W/" + etag))
            .map(e -> e.getKey())
            .findFirst()
            .orElse(null);

        if (key == null) {
            // no etag found
            return ResponseEntity.notFound().build();
        }

        String[] ks = key.split("\\|");
        String realm = ks[0];
        RealmLogo logo = realmManager.findLogo(realm);
        if (logo == null || logo.getImage() == null || logo.getImage().length == 0) {
            // no match
            return ResponseEntity.notFound().build();
        }

        String contentType = logo.getMimeType();
        String fileName = logo.getFileName();

        //check match
        if (!fileName.equals(ks[1])) {
            // no match
            return ResponseEntity.notFound().build();
        }

        int length = logo.getImage().length;
        ByteArrayInputStream inputStream = new ByteArrayInputStream(logo.getImage());

        return ResponseEntity.ok()
            .contentLength(length)
            .contentType(MediaType.parseMediaType(contentType))
            .cacheControl(CacheControl.maxAge(3600, TimeUnit.SECONDS).mustRevalidate())
            .eTag(etag)
            .body(new InputStreamResource(inputStream));
    }

    private String computeWeakEtag(InputStream is) throws IOException {
        StringBuilder builder = new StringBuilder();
        // use same pattern as shallow etag filter
        builder.append("W/");
        // builder.append("\"0");
        DigestUtils.appendMd5DigestAsHex(is, builder);
        // builder.append('"');
        return builder.toString();
    }
}
