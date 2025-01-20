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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManager;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManagerImpl;
import org.wso2.carbon.identity.x509Certificate.validation.validator.CRLValidator;
import org.wso2.carbon.identity.x509Certificate.validation.validator.OCSPValidator;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "validation.X509Certificate.service",
        immediate = true)
public class X509CertificateValidationServiceComponent {

    private static final Log log = LogFactory.getLog(X509CertificateValidationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        context.getBundleContext().registerService(RevocationValidationManager.class.getName(),
                new RevocationValidationManagerImpl(), null);
        CertificateValidationUtil.addDefaultValidationConfigInRegistry();
        CertificateValidationUtil.loadCRLDownloadTimeoutFromConfig();
        context.getBundleContext().registerService(RevocationValidator.class.getName(),
                new CRLValidator(), null);
        context.getBundleContext().registerService(RevocationValidator.class.getName(),
                new OCSPValidator(), null);
        context.getBundleContext().registerService(TenantMgtListener.class.getName(),
                new TenantManagementListener(), null);
    }

    @Deactivate
    protected void deactivate(ComponentContext componentContext) {

        if (log.isDebugEnabled()) {
            log.debug("X509 Certificate Validation bundle is de-activated.");
        }
    }

    @Reference(
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        CertValidationDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset Registry service.");
        }
        CertValidationDataHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        CertValidationDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
        CertValidationDataHolder.getInstance().setRealmService(null);
    }

    /**
     * Set the ConfigurationManager.
     *
     * @param configurationManager The {@code ConfigurationManager} instance.
     */
    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        log.debug("Registering the ConfigurationManager in Certificate Validation Service Component.");
        CertValidationDataHolder.getInstance().setConfigurationManager(configurationManager);
    }


    /**
     * Unset the ConfigurationManager.
     *
     * @param configurationManager The {@code ConfigurationManager} instance.
     */
    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        log.debug("Unregistering the ConfigurationManager in Certificate Validation Service Component.");
        CertValidationDataHolder.getInstance().setConfigurationManager(null);
    }
}
