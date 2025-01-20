/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for certificate revocation validation component.
 */
public class CertValidationDataHolder {

    private static RegistryService registryService;
    private static RealmService realmService;
    private static CertValidationDataHolder instance = new CertValidationDataHolder();
    private ConfigurationManager configurationManager = null;

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

    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
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

}
