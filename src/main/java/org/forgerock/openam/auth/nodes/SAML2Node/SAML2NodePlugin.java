/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes.SAML2Node;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmLookupException;
import org.forgerock.openam.core.realms.Realms;
import org.forgerock.openam.plugins.PluginException;
import org.forgerock.util.Pair;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.sm.OrganizationConfigManager;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;


/**
 * Definition of an
 * <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/auth/node/api/AbstractNodeAmPlugin.html">AbstractNodeAmPlugin</a>.
 * Implementations can use {@code @Inject} setters to get access to APIs
 * available via Guice dependency injection. For example, if you want to add an SMS service on install, you
 * can add the following setter:
 * <pre><code>
 * {@code @Inject}
 * public void setPluginTools(PluginTools tools) {
 *     this.tools = tools;
 * }
 * </code></pre>
 * So that you can use the addSmsService api to load your schema XML for example.
 * PluginTools javadoc may be found
 * <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/plugins/PluginTools.html#addSmsService-java.io.InputStream-">here</a>
 * <p>
 * It can be assumed that when running, implementations of this class will be singleton instances.
 * </p>
 * <p>
 * It should <i>not</i> be expected that the runtime singleton instances will be the instances on which
 * {@link #onAmUpgrade(String, String)} will be called. Guice-injected properties will also <i>not</i> be populated
 * during that method call.
 * </p>
 * <p>
 * Plugins should <i>not</i> use the {@code ShutdownManager}/{@code ShutdownListener} API for handling shutdown, as
 * the order of calling those listeners is not deterministic. The {@link #onShutdown()} method for all plugins will
 * be called in the reverse order from the order that {@link #onStartup()} was called, with dependent plugins being
 * notified after their dependencies for startup, and before them for shutdown.
 * </p>
 *
 * @supported.all.api
 * @since AM 5.5.0
 */
public class SAML2NodePlugin extends AbstractNodeAmPlugin {

	protected static final String NAME_ID_FORMAT = "nameIdFormat";
	static private String currentVersion = "1.0.7";
    private CoreWrapper coreWrapper;

    /**
     * DI-enabled constructor.
     *
     * @param coreWrapper
     */
    @Inject
    public SAML2NodePlugin(CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;

    }

    /**
     * Specify the Map of list of node classes that the plugin is providing. These will then be installed and
     * registered at the appropriate times in plugin lifecycle.
     *
     * @return The list of node classes.
     */
    @Override
    protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
        return Collections.singletonMap(SAML2NodePlugin.currentVersion,
                                        Arrays.asList(SAML2Node.class,
                                                      WriteFederationInformation.class));
    }

    /**
     * Handle plugin installation. This method will only be called once, on first AM startup once the plugin
     * is included in the classpath. The {@link #onStartup()} method will be called after this one.
     * <p>
     * No need to implement this unless your AuthNode has specific requirements on install.
     */
    @Override
    public void onInstall() throws PluginException {
        super.onInstall();
    }

    /**
     * Handle plugin startup. This method will be called every time AM starts, after {@link #onInstall()},
     * {@link #onAmUpgrade(String, String)} and {@link #upgrade(String)} have been called (if relevant).
     * <p>
     * No need to implement this unless your AuthNode has specific requirements on startup.
     *
     * @param startupType The type of startup that is taking place.
     */
    @Override
    public void onStartup() throws PluginException {
        super.onStartup();
    }

    /**
     * This method will be called when the version returned by {@link #getPluginVersion()} is higher than the
     * version already installed. This method will be called before the {@link #onStartup()} method.
     * <p>
     * No need to implement this untils there are multiple versions of your auth node.
     *
     * @param fromVersion The old version of the plugin that has been installed.
     */
    @Override
    public void upgrade(String fromVersion) throws PluginException {
        try {
            SSOToken token = coreWrapper.getAdminToken();
            String serviceName = SAML2Node.class.getSimpleName();
            ServiceConfigManager configManager = new ServiceConfigManager(serviceName, token);

            // Read all the values from all node in all the realms that will need replacing
            OrganizationConfigManager realmManager = new OrganizationConfigManager(token, "/");
            Set<String> realms = ImmutableSet.<String>builder()
                                             .add("/")
                                             .addAll(realmManager.getSubOrganizationNames("*", true))
                                             .build();
            Map<Pair<Realm, String>, String> oldValues = new HashMap<>();
            for (String realm : realms) {
                ServiceConfig container = configManager.getOrganizationConfig(realm, null);
                for (String nodeId : container.getSubConfigNames()) {
                    ServiceConfig nodeConfig = container.getSubConfig(nodeId);
                    String name = nodeConfig.getAttributes().get(NAME_ID_FORMAT).iterator().next();
                    oldValues.put(Pair.of(Realms.of(realm), nodeId), name);
                }
            }

            // Do the upgrade of the schema
            pluginTools.upgradeAuthNode(SAML2Node.class);

            // Remove the old value and set the new values
            for (Map.Entry<Pair<Realm, String>, String> nameIdFormatForUpdate : oldValues.entrySet()) {
                String realm = nameIdFormatForUpdate.getKey().getFirst().asPath();
                String nodeId = nameIdFormatForUpdate.getKey().getSecond();
                String name = nameIdFormatForUpdate.getValue();

                ServiceConfig container = configManager.getOrganizationConfig(realm, null);
                ServiceConfig nodeConfig = container.getSubConfig(nodeId);
                if (StringUtils.equals("UNSPECIFIED", name)) {
                    nodeConfig.setAttributes(ImmutableMap.of(NAME_ID_FORMAT, Collections.singleton(
                            SAML2Node.NameIdFormat.UNSPECIFIED_SAML2.name())));
                }
            }
        } catch (SSOException | SMSException | RealmLookupException e) {
            throw new PluginException("Could not upgrade", e);
        }
        super.upgrade(fromVersion);
    }

    /**
     * The plugin version. This must be in semver (semantic version) format.
     *
     * @return The version of the plugin.
     * @see <a href="https://www.osgi.org/wp-content/uploads/SemanticVersioning.pdf">Semantic Versioning</a>
     */
    @Override
    public String getPluginVersion() {
        return SAML2NodePlugin.currentVersion;
    }
}
