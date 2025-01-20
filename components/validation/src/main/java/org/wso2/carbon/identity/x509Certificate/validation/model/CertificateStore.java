/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.x509Certificate.validation.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CertificateStore {

    private static CertificateStore instance;
    private static final Object lock = new Object();

    // Outer map: key is the common path, inner map: key is the serial number
    private final Map<String, Map<String, CACertificate>> certificateStore;

    private CertificateStore() {
        certificateStore = new HashMap<>();
    }

    public static CertificateStore getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new CertificateStore();
                }
            }
        }
        return instance;
    }

    /**
     * Add a certificate to the store under a given path and serial number.
     */
    public void addCertificate(String commonPath, String serialNumber, CACertificate certificate) {
        certificateStore
                .computeIfAbsent(commonPath, k -> new HashMap<>())
                .put(serialNumber, certificate);
    }

    /**
     * Get all certificates for a given common path.
     */
    public List<CACertificate> getCertificates(String commonPath) {
        Map<String, CACertificate> certificates = certificateStore.get(commonPath);
        return certificates != null ? new ArrayList<>(certificates.values()) : new ArrayList<>();
    }

    /**
     * Check if the store contains any certificates for a given common path.
     */
    public boolean containsCertificates(String commonPath) {
        return certificateStore.containsKey(commonPath);
    }

    /**
     * Check if a specific certificate exists under a given common path.
     */
    public boolean containsCertificate(String commonPath, String serialNumber) {
        Map<String, CACertificate> certificates = certificateStore.get(commonPath);
        return certificates != null && certificates.containsKey(serialNumber);
    }

    /**
     * Get a specific certificate by its serial number under a given common path.
     */
    public CACertificate getCertificate(String commonPath, String serialNumber) {
        Map<String, CACertificate> certificates = certificateStore.get(commonPath);
        return certificates != null ? certificates.get(serialNumber) : null;
    }
}
