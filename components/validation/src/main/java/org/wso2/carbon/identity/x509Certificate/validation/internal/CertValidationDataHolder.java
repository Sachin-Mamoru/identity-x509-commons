/*
 * Copyright (c) 2018-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.x509Certificate.validation.internal;

import org.wso2.carbon.identity.certificate.management.service.CertificateManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.x509Certificate.validation.service.X509AuthenticatorCertificateManager;
import org.wso2.carbon.identity.x509Certificate.validation.service.X509AuthenticatorValidatorManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for certificate revocation validation component.
 */
public class CertValidationDataHolder {

    private static RegistryService registryService;
    private static RealmService realmService;
    private static CertValidationDataHolder instance = new CertValidationDataHolder();
    private static ConfigurationManager configurationManager;
    private static CertificateManagementService certificateManagementService;
    private static X509AuthenticatorValidatorManager x509AuthenticatorValidatorManager;
    private static X509AuthenticatorCertificateManager x509AuthenticatorCertificateManager;

    private CertValidationDataHolder() {
    }

    /**
     * Get certificate validation data holder instance.
     *
     * @return CertValidationDataHolder instance
     */
    public static CertValidationDataHolder getInstance() {

        return instance;
    }

    /**
     * Get registry service.
     *
     * @return registry service
     */
    public RegistryService getRegistryService() {

        return registryService;
    }

    /**
     * Set registry service.
     *
     * @param service registry service
     */
    public void setRegistryService(RegistryService service) {

        this.registryService = service;
    }

    /**
     * Get realm service.
     *
     * @return realm service
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set realm service.
     *
     * @param realmService realm service
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Set Configuration Manager.
     *
     * @param configurationManager configuration manager
     */
    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    /**
     * Get Configuration Manager.
     *
     * @return configuration manager
     */
    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    /**
     * Set Certificate Management Service.
     *
     * @param service certificate management service
     */
    public void setCertificateManagementService(CertificateManagementService service) {

        this.certificateManagementService = service;
    }

    /**
     * Get Certificate Management Service.
     *
     * @return certificate management service
     */
    public CertificateManagementService getCertificateManagementService() {

        return certificateManagementService;
    }

    /**
     * Set X509 Authenticator Validator Manager.
     *
     * @param x509AuthenticatorValidatorManager x509 authenticator validator manager
     */
    public void setX509AuthenticatorValidatorManager(X509AuthenticatorValidatorManager x509AuthenticatorValidatorManager) {

        this.x509AuthenticatorValidatorManager = x509AuthenticatorValidatorManager;
    }

    /**
     * Get X509 Authenticator Validator Manager.
     *
     * @return x509 authenticator validator manager
     */
    public X509AuthenticatorValidatorManager getX509AuthenticatorValidatorManager() {

        return x509AuthenticatorValidatorManager;
    }

    /**
     * Set X509 Authenticator Certificate Manager.
     *
     * @param x509AuthenticatorCertificateManager x509 authenticator certificate manager
     */
    public void setX509AuthenticatorCertificateManager(X509AuthenticatorCertificateManager x509AuthenticatorCertificateManager) {

        this.x509AuthenticatorCertificateManager = x509AuthenticatorCertificateManager;
    }

    /**
     * Get X509 Authenticator Certificate Manager.
     *
     * @return x509 authenticator certificate manager
     */
    public X509AuthenticatorCertificateManager getX509AuthenticatorCertificateManager() {

        return x509AuthenticatorCertificateManager;
    }
}
