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

import static java.util.stream.Collectors.toMap;
import static org.forgerock.http.util.Uris.urlEncodeQueryParameterNameOrValue;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.EMAIL_ADDRESS;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.ATTRIBUTES_SHARED_STATE_KEY;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.USER_INFO_SHARED_STATE_KEY;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.USER_NAMES_SHARED_STATE_KEY;
import static org.forgerock.openam.utils.Time.currentTimeMillis;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.AbstractSocialAuthLoginNode;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.authentication.modules.oauth2.OAuthUtil;
import org.forgerock.openam.authentication.modules.saml2.SAML2Proxy;
import org.forgerock.openam.authentication.modules.saml2.SAML2ResponseData;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.federation.saml2.SAML2TokenRepositoryException;
import org.forgerock.openam.ldap.LDAPUtils;
import org.forgerock.openam.saml2.SAML2Store;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.xui.XUIState;
import org.forgerock.opendj.ldap.Dn;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.client.AuthClientUtils;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.EncryptedID;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.assertion.Subject;
import com.sun.identity.saml2.common.AccountUtils;
import com.sun.identity.saml2.common.NameIDInfo;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2FailoverUtils;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.jaxb.entityconfig.SPSSOConfigElement;
import com.sun.identity.saml2.jaxb.metadata.AffiliationDescriptorType;
import com.sun.identity.saml2.jaxb.metadata.EndpointType;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorType;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorType;
import com.sun.identity.saml2.key.KeyUtil;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.plugins.DefaultLibrarySPAccountMapper;
import com.sun.identity.saml2.plugins.SAML2PluginsUtils;
import com.sun.identity.saml2.plugins.SPAccountMapper;
import com.sun.identity.saml2.plugins.SPAttributeMapper;
import com.sun.identity.saml2.profile.AuthnRequestInfo;
import com.sun.identity.saml2.profile.AuthnRequestInfoCopy;
import com.sun.identity.saml2.profile.ResponseInfo;
import com.sun.identity.saml2.profile.SPACSUtils;
import com.sun.identity.saml2.profile.SPCache;
import com.sun.identity.saml2.profile.SPSSOFederate;
import com.sun.identity.saml2.protocol.AuthnRequest;
import com.sun.identity.shared.encode.CookieUtils;
import com.sun.identity.shared.locale.L10NMessageImpl;
import com.sun.identity.sm.RequiredValueValidator;

import java.security.Principal;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * SAML2 Node
 */
@Node.Metadata(outcomeProvider  = AbstractSocialAuthLoginNode.SocialAuthOutcomeProvider.class,
               configClass      = SAML2Node.Config.class)
public class SAML2Node extends AbstractDecisionNode {

    public static final String CACHE_KEY = "cacheKey";
    public static final String IS_TRANSIENT = "isTransient";
    public static final String REQUEST_ID = "requestId";

    private static final String BUNDLE_NAME = "amAuthSAML2";
    private ResourceBundle bundle = null;
    private static final String BUNDLE = "org.forgerock.openam.auth.nodes.SAML2Node";



    private final Logger logger = LoggerFactory.getLogger(SAML2Node.class);
    private Map<String, List<String>> params = new HashMap<>();

    private final Config config;
    private final Realm realm;

    private final CoreWrapper coreWrapper;
    private String nameIDFormat;
    private final String entityName;
    private final String metaAlias;
    private String reqBinding;
    private Binding binding;
    private final String localChain;
    private final boolean singleLogoutEnabled;
    private final String sloRelayState;
    private final SAML2MetaManager metaManager;
    private AuthnRequest authnRequest;
    private AuthContext authenticationContext;
    private String storageKey;
    private Subject assertionSubject;
    private Assertion authnAssertion;
    private String sessionIndex;
    private ResponseInfo respInfo;
    private boolean isTransient;
    private Principal principal;
    private SocialOAuth2Helper authNodeHelper;


    private static final String MAIL_KEY_MAPPING = "mail";
    private static final String PROPERTY_VALUES_SEPARATOR = "|";




    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default String entityName() { return "http://"; }

        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        default String metaAlias() { return "/sp"; }

        @Attribute(order = 300)
        default boolean allowCreate() { return true; }

        @Attribute(order = 400)
        default String localChain() { return ""; }

        @Attribute(order = 500)
        default AuthComparision authComparision() { return AuthComparision.EXACT; }

        @Attribute(order = 600)
        default String authnContextClassRef() { return ""; }

        @Attribute(order = 700)
        default String authNContextDeclRef() { return ""; }

        @Attribute(order = 800)
        default RequestBinding reqBinding() { return RequestBinding.HTTP_REDIRECT; }

        @Attribute(order = 900)
        default Binding binding() { return Binding.HTTP_ARTIFACT; }

        @Attribute(order = 1000)
        default boolean forceAuthn() { return false; }

        @Attribute(order = 1100)
        default boolean isPassive() { return false; }

        @Attribute(order = 1200)
        default String nameIdFormat() { return "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"; }

        @Attribute(order = 1300)
        default boolean sloEnabled() { return false; }

        @Attribute(order = 1400)
        default String sloRelay() { return "http://"; }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public SAML2Node(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper,
                      SocialOAuth2Helper authNodeHelper) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
        this.coreWrapper = coreWrapper;
        this.authNodeHelper = authNodeHelper;

        nameIDFormat = config.nameIdFormat();
        entityName = config.entityName();
        metaAlias = config.metaAlias();
        reqBinding = config.reqBinding().toString();
        binding = config.binding();
        localChain = config.localChain();
        singleLogoutEnabled = config.sloEnabled();
        sloRelayState = config.sloRelay();
        metaManager = SAML2Utils.getSAML2MetaManager();
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        this.bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE_NAME, getClass().getClassLoader());
        String spName = null;

        final HttpServletRequest request = context.request.servletRequest;
        final HttpServletResponse response = context.request.servletResponse;

        if (null == request) {
            throw new NodeProcessException("Unable to login without http request.  Programmatic login is not " +
                                                    "supported.");

        }
        try {
            spName = metaManager.getEntityByMetaAlias(metaAlias);
            if (authenticationContext != null) {
                //TODO Add error handling here
            }
        } catch (SAML2MetaException e) {
            e.printStackTrace();
        }
        try {
            //If responseKey is in the query parameters, we have been redirected back from IdP
            if (context.request.parameters.containsKey("responsekey")) {
                return handleReturnFromRedirect(context, request, spName, response).build();
            }
            //Otherwise redirect to IDP
            return Action.send(initiateSAMLLoginAtIDP(request, response)).build();

        } catch (SAML2Exception | AuthLoginException e) {
            throw new NodeProcessException(e);
        }


    }

    /**
     * Performs similar to SPSSOFederate.initiateAuthnRequest by returning to the next auth stage
     * with a redirect (either GET or POST depending on the config) which triggers remote IdP authentication.
     */
    private Callback initiateSAMLLoginAtIDP(HttpServletRequest request, HttpServletResponse response)
            throws SAML2Exception, AuthLoginException, NodeProcessException {


        final String spEntityID = SPSSOFederate.getSPEntityId(metaAlias);
        final IDPSSODescriptorType idpsso = SPSSOFederate.getIDPSSOForAuthnReq(realm.toString(), entityName);
        final SPSSODescriptorType spsso = SPSSOFederate.getSPSSOForAuthnReq(realm.toString(), spEntityID);

        if (idpsso == null || spsso == null) {
            throw new NodeProcessException("Failed to load SAML2 Configuration.");

        }

        List<EndpointType> ssoServiceList = idpsso.getSingleSignOnService();
        final EndpointType endPoint = SPSSOFederate
                .getSingleSignOnServiceEndpoint(ssoServiceList, reqBinding.toString());

        if (endPoint == null || StringUtils.isEmpty(endPoint.getLocation())) {
            throw new SAML2Exception(SAML2Utils.bundle.getString("ssoServiceNotfound"));
        }
        if (reqBinding == null) {
            logger.debug("SAML2 :: initiateSAMLLoginAtIDP() reqBinding is null using endpoint  binding: {}",
                          endPoint.getBinding());
            reqBinding = endPoint.getBinding();
            if (reqBinding == null) {
                throw new SAML2Exception(SAML2Utils.bundle.getString("UnableTofindBinding"));
            }
        }

        String ssoURL = endPoint.getLocation();
        logger.debug("SAML2 :: initiateSAMLLoginAtIDP()  ssoURL : {}", ssoURL);

        final List extensionsList = SPSSOFederate.getExtensionsList(spEntityID, String.valueOf(realm));
        final Map<String, Collection<String>> spConfigAttrsMap
                = SPSSOFederate.getAttrsMapForAuthnReq(String.valueOf(realm), spEntityID);


        authnRequest = SPSSOFederate.createAuthnRequest(request, response, realm.toString(), spEntityID, entityName,
                                                        params, spConfigAttrsMap, extensionsList, spsso, idpsso,
                                                        ssoURL, false);

        final AuthnRequestInfo reqInfo = new AuthnRequestInfo(request, response, realm.toString(), spEntityID, null,
                                                               authnRequest, null, params);

        synchronized (SPCache.requestHash) {
            SPCache.requestHash.put(authnRequest.getID(), reqInfo);
        }

        saveAuthnRequest(authnRequest, reqInfo);

        final RedirectCallback redirectCallback = new RedirectCallback();
        setCookiesForRedirects(request, response);

        //we only handle Redirect and POST
        if (SAML2Constants.HTTP_POST.equals(reqBinding)) {
            final String postMsg = SPSSOFederate.getPostBindingMsg(idpsso, spsso, spConfigAttrsMap, authnRequest);
            return (configurePostRedirectCallback(postMsg, ssoURL, redirectCallback));
        } else {
            final String authReqXMLString = authnRequest.toXMLString(true, true);
            final String redirectUrl = SPSSOFederate.getRedirect(authReqXMLString, null, ssoURL, idpsso,
                                                                 spsso, spConfigAttrsMap);
            return (configureGetRedirectCallback(redirectUrl, redirectCallback));
        }
    }

    /**
     * Once we're back from the ACS, we need to validate that we have not errored during the proxying process.
     * Then we detect if we need to perform a local linking authentication chain, or if the user is already
     * locally linked, we need to look up the already-linked username.
     */
    private Action.ActionBuilder handleReturnFromRedirect(TreeContext context, final HttpServletRequest request,
                                                          final String spName,
                                                          final HttpServletResponse response)
            throws AuthLoginException, NodeProcessException {

        ExternalRequestContext externalRequestContext = context.request;

        removeCookiesForRedirects(request, response);

        if (Boolean.parseBoolean(externalRequestContext.parameters.get(SAML2Proxy.ERROR_PARAM_KEY).get(0))) {
            handleRedirectError(externalRequestContext);
        }

        String key = null;
        if (externalRequestContext.parameters.get("jsonContent") != null) {
            key = JsonValueBuilder.toJsonValue(externalRequestContext.parameters.get("jsonContent").get(0)).get(
                    "responsekey").asString();
        } else {
            List<String> keys = externalRequestContext.parameters.get(SAML2Proxy.RESPONSE_KEY);
            if (!keys.isEmpty()) {
                key = keys.get(0);
            }
        }

        SAML2ResponseData data = null;

        if (!StringUtils.isBlank(key)) {
            data = (SAML2ResponseData) SAML2Store.getTokenFromStore(key);

            if (data == null) {
                if (SAML2FailoverUtils.isSAML2FailoverEnabled()) {
                    try {
                        data = (SAML2ResponseData) SAML2FailoverUtils.retrieveSAML2Token(key);
                    } catch (SAML2TokenRepositoryException e) {
                        processError(bundle.getString("samlFailoverError"), "SAML2.handleReturnFromRedirect : Error " +
                                "reading from failover map.", e);
                    }
                }
            }
        }

        if (data == null) {
            processError(bundle.getString("localLinkError"), "SAML2 :: handleReturnFromRedirect() : Unable to perform" +
                    " local linking - response data not found");
        }

        storageKey = key;
        assertionSubject = data.getSubject();
        authnAssertion = data.getAssertion();
        sessionIndex = data.getSessionIndex();
        respInfo = data.getResponseInfo();
        JsonValue sharedState = context.sharedState;

        final EncryptedID encId = assertionSubject.getEncryptedID();
        final SPSSOConfigElement spssoconfig;
        final SPAccountMapper acctMapper;
        try {
            spssoconfig = metaManager.getSPSSOConfig(realm.toString(), spName);
            acctMapper = SAML2Utils.getSPAccountMapper(realm.toString(), spName);
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }
        final Set<PrivateKey> decryptionKeys = KeyUtil.getDecryptionKeys(spssoconfig);
        boolean needNameIDEncrypted = false;
        NameID nameId = assertionSubject.getNameID();

        String assertionEncryptedAttr =
                SAML2Utils.getAttributeValueFromSPSSOConfig(spssoconfig, SAML2Constants.WANT_ASSERTION_ENCRYPTED);
        if (!Boolean.parseBoolean(assertionEncryptedAttr)) {
            String idEncryptedStr =
                    SAML2Utils.getAttributeValueFromSPSSOConfig(spssoconfig, SAML2Constants.WANT_NAMEID_ENCRYPTED);
            needNameIDEncrypted = Boolean.parseBoolean(idEncryptedStr);
        }

        if (needNameIDEncrypted && encId == null) {
            throw new NodeProcessException(SAML2Utils.bundle.getString("nameIDNotEncrypted"));
        }
        if (encId != null) {
            try {
                nameId = encId.decrypt(decryptionKeys);
            } catch (SAML2Exception e) {
                throw new NodeProcessException(e);
            }
        }

        SPSSODescriptorType spDesc = null;
        try {
            spDesc = metaManager.getSPSSODescriptor(realm.toString(), spName);
        } catch (SAML2MetaException ex) {
            logger.error("Unable to read SPSSODescription", ex);
        }

        if (spDesc == null) {
            throw new NodeProcessException(SAML2Utils.bundle.getString("metaDataError"));
        }

        final String nameIDFormat = config.nameIdFormat();
        if (nameIDFormat != null) {
            List spNameIDFormatList = spDesc.getNameIDFormat();

            if (CollectionUtils.isNotEmpty(spNameIDFormatList) && !spNameIDFormatList.contains(nameIDFormat)) {
                throw new NodeProcessException("Unsupported NameIDFormat SP: " + nameIDFormat);
            }
        }

        final boolean isTransient = SAML2Constants.NAMEID_TRANSIENT_FORMAT.equals(nameIDFormat);
        final boolean disableNameIDPersistence = !acctMapper.shouldPersistNameIDFormat(realm.toString(), spName,
                                                                                       entityName, nameIDFormat);
        final boolean persistNameId = !isTransient && !disableNameIDPersistence;

        Map nameIdKeyMap;
        try {
            nameIdKeyMap = SAML2Utils.getNameIDKeyMap(nameId, spName, entityName, realm.toString(), SAML2Constants.SP_ROLE);
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }

        String username = null;
        //If nameID format isn't transient and we should should persist name ID returns true, then look for user via
        // nameID
        if (persistNameId) {
            try {
                username = SAML2Utils.getDataStoreProvider().getUserID(realm.toString(), nameIdKeyMap);
                if (StringUtils.isNotEmpty(username)) {
                    AMIdentity identity;
                    try {
                        identity = new AMIdentity(null, username);
                    } catch (IdRepoException e) {
                        throw new NodeProcessException(e);
                    }
                    String univ = identity.getName();
                    return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                                 .replaceSharedState(sharedState.put(SharedStateConstants.USERNAME, univ));
                }
            } catch (DataStoreProviderException | SAML2Exception e) {
                throw new NodeProcessException(e);
            }
        }

        // If we haven't found the user yet, use the configured account mapper to find the user based on auto
        // federation or transient user configuration
        if (StringUtils.isEmpty(username)) {
            try {
                username = acctMapper.getIdentity(authnAssertion, spName, realm.toString());
                if (StringUtils.isNotEmpty(username)) {
                    try {
                        AMIdentity identity = new AMIdentity(null, username);
                        String univ = identity.getName();
                        if (persistNameId) {
                            try {
                                final NameIDInfo info;
                                final String affiID = nameId.getSPNameQualifier();
                                boolean isDualRole = SAML2Utils.isDualRole(spName, realm.toString());
                                AffiliationDescriptorType affiDesc = null;

                                if (affiID != null && !affiID.isEmpty()) {
                                    affiDesc = metaManager.getAffiliationDescriptor(realm.toString(), affiID);
                                }

                                if (affiDesc != null) {
                                    if (!affiDesc.getAffiliateMember().contains(spName)) {
                                        throw new SAML2Exception("Unable to locate SP Entity ID in the affiliate descriptor.");
                                    }
                                    if (isDualRole) {
                                        info = new NameIDInfo(affiID, entityName, nameId, SAML2Constants.DUAL_ROLE, true);
                                    } else {
                                        info = new NameIDInfo(affiID, entityName, nameId, SAML2Constants.SP_ROLE, true);
                                    }
                                } else {
                                    if (isDualRole) {
                                        info = new NameIDInfo(spName, entityName, nameId, SAML2Constants.DUAL_ROLE, false);
                                    } else {
                                        info = new NameIDInfo(spName, entityName, nameId, SAML2Constants.SP_ROLE, false);
                                    }
                                }

                                // write fed info into data store
                                SPCache.fedAccountHash.put(storageKey, "true");
                                AccountUtils.setAccountFederation(info, username);
                            } catch (SAML2Exception se) {
                                throw new NodeProcessException(se);
                            }
                        }
                        return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                                     .replaceSharedState(sharedState.put(SharedStateConstants.USERNAME, univ));
                    } catch (IdRepoException e) {
                        return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.NO_ACCOUNT.name())
                                     .replaceSharedState(setupAttributes(spName, sharedState, persistNameId, username));
                    }
                }


            } catch (SAML2Exception e) {
                throw new NodeProcessException(e);
            }
        }



        return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.NO_ACCOUNT.name())
                     .replaceSharedState(setupAttributes(spName, sharedState, persistNameId, username));

    }

    private JsonValue setupAttributes(String spName, JsonValue sharedState, boolean persistNameId, String username1)
            throws NodeProcessException, AuthLoginException {
        Map<String, Set<String>> attributes;
        try {
            attributes = linkAttributeValues(authnAssertion, username1);
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }
        NameIDInfo info;
        try {
            if (persistNameId) {
                info = new NameIDInfo(spName, entityName, getNameId(), SAML2Constants.SP_ROLE,
                                      false);
                attributes.putAll(AccountUtils.convertToAttributes(info, null));
            }
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }

        synchronized (SPCache.authnRequestHash) {
            SPCache.authnRequestHash.put(storageKey, authnRequest);
        }

        sharedState.put(USER_INFO_SHARED_STATE_KEY, json(object(
                field(ATTRIBUTES_SHARED_STATE_KEY, convertToMapOfList(attributes)),
                field(USER_NAMES_SHARED_STATE_KEY,
                      convertToMapOfList(Collections.singletonMap(SharedStateConstants.USERNAME,
                                                                  Collections.singleton(username1)))))));

        if (attributes.get(MAIL_KEY_MAPPING) != null) {
            sharedState.put(EMAIL_ADDRESS, attributes.get(MAIL_KEY_MAPPING).stream().findAny().get());
        } else {
            logger.debug("Unable to ascertain email address because the information is not available. "
                                 +
                                 "It's possible you need to add a scope or that the configured provider does not have this "
                                 + "information");
        }
        return sharedState;
    }


    private Map<String, ArrayList<String>> convertToMapOfList(Map<String, Set<String>> mapToConvert) {
        return mapToConvert.entrySet().stream().collect(toMap(Map.Entry::getKey, e -> new ArrayList<>(e.getValue())));
    }


    private void saveAuthnRequest(final AuthnRequest authnRequest, final AuthnRequestInfo reqInfo)
            throws SAML2Exception {

        final long sessionExpireTimeInSeconds
                = TimeUnit.MILLISECONDS.toSeconds(currentTimeMillis()) + SPCache.interval;
        final String key = authnRequest.getID();

        if (SAML2FailoverUtils.isSAML2FailoverEnabled()) {
            try {
                SAML2FailoverUtils.saveSAML2TokenWithoutSecondaryKey(key, new AuthnRequestInfoCopy(reqInfo),
                                                                     sessionExpireTimeInSeconds);
                logger.info("SAML2.saveAuthnRequestIfFailoverEnabled : "
                                    + "SAVE AuthnRequestInfoCopy for requestID {}", key);
            } catch (SAML2TokenRepositoryException e) {
                logger.info("SAML2.saveAuthnRequestIfFailoverEnabled : There was a problem saving the "
                                    + "AuthnRequestInfoCopy in the SAML2 Token Repository for requestID {}", key, e);
                throw new SAML2Exception(BUNDLE_NAME, "samlFailover", null);
            }
        } else {
            SAML2Store.saveTokenWithKey(key, new AuthnRequestInfoCopy(reqInfo));
            logger.info("SAML2.saveAuthnRequestIfFailoverDisabled : SAVE AuthnRequestInfoCopy for requestID {}", key);
        }
    }

    /**
     * Generates the redirect from SAML2 auth module to IDP as POST.
     */
    private RedirectCallback configurePostRedirectCallback(final String postMsg, final String ssoURL,
                                               final RedirectCallback redirectCallback) throws AuthLoginException {
        final Map<String, String> postData = new HashMap<>();
        postData.put(SAML2Constants.SAML_REQUEST, postMsg);

        final RedirectCallback rcNew = new RedirectCallback(ssoURL, postData, "POST",
                                                            redirectCallback.getStatusParameter(), redirectCallback.getRedirectBackUrlCookieName());
        rcNew.setTrackingCookie(true);
        return rcNew;
    }

    /**
     * Generates the redirect from SAML2 auth node to IDP as GET.
     */
    private RedirectCallback configureGetRedirectCallback(final String redirectUrl, RedirectCallback redirectCallback)
            throws AuthLoginException {
        final RedirectCallback rcNew = new RedirectCallback(redirectUrl, null, "GET",
                                                            redirectCallback.getStatusParameter(), redirectCallback.getRedirectBackUrlCookieName());

        Map<String, String> redirectData = rcNew.getRedirectData();

        rcNew.setRedirectData(redirectData);
        rcNew.setTrackingCookie(true);
        return rcNew;
    }

    /**
     * Writes out an error debug (if a throwable and debug message are provided) and returns a user-facing
     * error page.
     */
    private void processError(String headerMessage, String debugMessage,
                             Object... messageParameters) throws AuthLoginException, NodeProcessException {
        if (null != debugMessage) {
            logger.error(debugMessage, messageParameters);
        }
        throw new NodeProcessException(headerMessage);
    }

    /**
     * Writes out an error debug (if a throwable and debug message are provided) and returns a user-facing
     * error page.
     */
    private void processError(Locale locale, L10NMessageImpl e, String headerMessageCode,
                              String debugMessage, Object... messageParameters)
            throws AuthLoginException, NodeProcessException {

        if (null == e) {
            processError(headerMessageCode, debugMessage, messageParameters);
        }
        String headerMessage;
        if (null == headerMessageCode) {
            headerMessage = e.getL10NMessage(locale);
        } else {
            headerMessage = bundle.getString(headerMessageCode);
        }
        if (debugMessage != null) {
            logger.error(debugMessage, messageParameters, e);
        }
        throw new NodeProcessException(headerMessage);
    }

    /**
     * Grab error code/message and display to user via processError.
     */
    private void handleRedirectError(ExternalRequestContext request) throws AuthLoginException, NodeProcessException {
        final String errorCode = String.valueOf(request.parameters.get(SAML2Proxy.ERROR_CODE_PARAM_KEY));
        final String errorMessage = String.valueOf(request.parameters.get(SAML2Proxy.ERROR_MESSAGE_PARAM_KEY));

        if (StringUtils.isNotEmpty(errorMessage)) {
            processError(errorMessage, "SAML2 :: handleReturnFromRedirect() : "
                    + "error forwarded from saml2AuthAssertionConsumer.jsp.  Error code - {}. "
                    + "Error message - {}", String.valueOf(errorCode), String.valueOf(errorMessage));
        } else if (StringUtils.isNotEmpty(errorCode)) {
            processError(bundle.getString(errorCode), "SAML2 :: handleReturnFromRedirect() : "
                    + "error forwarded from saml2AuthAssertionConsumer.jsp.  Error code - {}. "
                    + "Error message - {}", errorCode, errorMessage);
        } else {
            processError(bundle.getString("samlVerify"), "SAML2 :: handleReturnFromRedirect() : "
                    + "error forwarded from saml2AuthAssertionConsumer.jsp.  Error code - {}. "
                    + "Error message - {}", errorMessage);
        }
    }

//    /**
//     * Submits completed callbacks (from the just-completed step - the first time this is called realCallbacks should
//     * be null as there is no just-completed step in the internal auth module), and injects the next lot if there
//     * are any.
//     */
//    private int injectCallbacks(final Callback[] realCallbacks, final int state)
//            throws AuthLoginException, NodeProcessException {
//
//        if (authenticationContext.hasMoreRequirements()) {
//            //replace existing callbacks
//            if (realCallbacks != null) {
//                authenticationContext.submitRequirements(realCallbacks);
//            }
//
//            if (authenticationContext.hasMoreRequirements()) {
//                return injectAndReturn(state);
//            } else { //completed auth, status should be failure or success, allow stepLogin to return
//                return finishLoginModule(state);
//            }
//        }
//
//        processError(bundle.getString("invalidLoginState"),
//                            "SAML2 :: injectCallbacks() : Authentication Module - invalid login state");
//    }

//    /**
//     * Draws the next set of callbacks on to the current (externally-facing) auth module's step.
//     */
//    private int injectAndReturn(int state) throws AuthLoginException, NodeProcessException {
//        Callback[] injectedCallbacks = authenticationContext.getRequirements();
//
//        while (injectedCallbacks.length == 0) {
//            authenticationContext.submitRequirements(injectedCallbacks);
//            if (authenticationContext.hasMoreRequirements()) {
//                injectedCallbacks = authenticationContext.getRequirements();
//            } else { //completed auth with zero callbacks status should be failure or success, allow stepLogin to return
//                return finishLoginModule(state);
//            }
//        }
//
//        replaceHeader(LOGIN_STEP,
//                      ((PagePropertiesCallback)
//                              authenticationContext.getAuthContextLocal().getLoginState().getReceivedInfo()[0]).getHeader());
//        if (injectedCallbacks.length > MAX_CALLBACKS_INJECTED) {
//            processError(bundle.getString("samlLocalAuthFailed"),
//                                "SAML2 :: injectAndReturn() : Local authentication failed");
//        }
//
//        if (previousLength > 0) { //reset
//            for (int i = 0; i < previousLength; i++) {
//                replaceCallback(LOGIN_STEP, i, DEFAULT_CALLBACK);
//            }
//        }
//
//        for (int i = 0; i < injectedCallbacks.length; i++) {
//            replaceCallback(LOGIN_STEP, i, injectedCallbacks[i]);
//        }
//
//        previousLength = injectedCallbacks.length;
//
//        return LOGIN_STEP;
//    }

//
//    /**
//     * Finishes a login module and then progresses to the next state.
//     */
//    private int finishLoginModule(int state) throws AuthLoginException, NodeProcessException {
//        if (authenticationContext.getStatus().equals(AuthContext.Status.IN_PROGRESS)) {
//            processError(bundle.getString("invalidLoginState"),
//                                "SAML2 :: injectCallbacks() : Authentication Module - invalid login state");
//        }
//        return stepLogin(null, state);
//    }
//
//    /**
//     * In conjuncture with injectCallbacks, steps through an internal auth chain (stored in authenticationContext) until
//     * it's completed by repeatedly injecting the callbacks from the internal chain's modules and submitting
//     * them until the status has confirmed failed or succeeded.
//     */
//    private int stepLogin(final Callback[] realCallbacks, final int state, Locale locale)
//            throws AuthLoginException, NodeProcessException {
//
//        if (authenticationContext == null || authenticationContext.getStatus().equals(AuthContext.Status.FAILED)) {
//            processError(bundle.getString("samlLocalAuthFailed"),
//                                "SAML2 :: process() : failed to perform local authentication - {} ",
//                                bundle.getString("samlLocalAuthFailed"));
//        } else if (authenticationContext.getStatus().equals(AuthContext.Status.IN_PROGRESS)) {
//            return injectCallbacks(realCallbacks, state);
//        } else if (authenticationContext.getStatus().equals(AuthContext.Status.SUCCESS)) {
//            try {
//                final NameID nameId = getNameId();
//                final String userName = authenticationContext.getSSOToken().getProperty(UNIVERSAL_IDENTIFIER);
//                linkAccount(userName, nameId);
//                return success(authnAssertion, nameId, userName);
//            } catch (L10NMessageImpl l10NMessage) {
//                 processError(locale, l10NMessage, null, "SAML2 :: process() : failed to perform local authentication" +
//                         " - {} ", l10NMessage.getL10NMessage(locale));
//            } finally {
//                authenticationContext.logout();
//            }
//        }
//
//        processError(bundle.getString("invalidLoginState"), "SAML2 :: stepLogin() : unexpected login state");
//    }
//
//    /**
//     * Sets the auth module's logged-in username via storeUsernamePasswd, triggers call
//     * to add information necessary for SLO (if configured) and returns success.
//     */
//    private int success(Assertion assertion, NameID nameId, String userName) throws AuthLoginException, SAML2Exception {
//        Action.ActionBuilder actionBuilder = setSessionProperties(assertion, nameId, userName);
//        setSessionAttributes(assertion, userName);
//        logger.info("SAML2 :: User Authenticated via SAML2 - {}", context.sharedState.get(SharedStateConstants.USERNAME));
//        storeUsernamePasswd(DNUtils.DNtoName(getPrincipal().getName()), null);
//        return ISAuthConstants.LOGIN_SUCCEED;
//    }

    /**
     * Adds information necessary for the session to be federated completely (if attributes are being
     * drawn in, and to configure ready for SLO).
     */
    private Action.ActionBuilder setSessionProperties(Action.ActionBuilder actionBuilder, NameID nameId)
            throws AuthLoginException, SAML2Exception {
        //if we support single logout sp initiated from the auth node's resulting session
        actionBuilder.putSessionProperty(SAML2Constants.SINGLE_LOGOUT, String.valueOf(singleLogoutEnabled));

        if (singleLogoutEnabled && StringUtils.isNotEmpty(sloRelayState)) { //we also need to store the relay state
            actionBuilder.putSessionProperty(SAML2Constants.RELAY_STATE, sloRelayState);
            // RelayState property name is not unique and can be overwritten in session, so also store separately
            actionBuilder.putSessionProperty(SAML2Constants.SINGLE_LOGOUT_URL, sloRelayState);
        }

        //we need the following for idp initiated slo as well as sp, so always include it
        if (sessionIndex != null) {
            actionBuilder.putSessionProperty(SAML2Constants.SESSION_INDEX, sessionIndex);
        }
        actionBuilder.putSessionProperty(SAML2Constants.IDPENTITYID, entityName);
        actionBuilder.putSessionProperty(SAML2Constants.SPENTITYID, SPSSOFederate.getSPEntityId(metaAlias));
        actionBuilder.putSessionProperty(SAML2Constants.METAALIAS, metaAlias);
        actionBuilder.putSessionProperty(SAML2Constants.REQ_BINDING, reqBinding);
        actionBuilder.putSessionProperty(SAML2Constants.NAMEID, nameId.toXMLString(true, true));
        actionBuilder.putSessionProperty(IS_TRANSIENT, Boolean.toString(isTransient));
        actionBuilder.putSessionProperty(REQUEST_ID, respInfo.getResponse().getInResponseTo());
        actionBuilder.putSessionProperty(SAML2Constants.BINDING, binding.toString());
        actionBuilder.putSessionProperty(CACHE_KEY, storageKey);
        return actionBuilder;
    }

    /**
     * Also pushes the authnRequest into a local cache so that it - alongside the storage key used to retrieve the
     * response data - can be used to call into SAML2ServiceProviderAdapter methods.
     */
//    private void setSessionAttributes(Assertion assertion, String userName) throws AuthLoginException, SAML2Exception {
//        synchronized (SPCache.authnRequestHash) {
//            SPCache.authnRequestHash.put(storageKey, authnRequest);
//        }
//
//        linkAttributeValues(assertion, userName);
//    }

    /**
     * Performs the functions of linking attribute values that have been received from the assertion
     * by building them into appropriate strings and asking the auth service to migrate them into session
     * properties once authentication is completed.
     */
    private Map<String, Set<String>> linkAttributeValues(Assertion assertion, String userName)
            throws SAML2Exception {

        final String spName = metaManager.getEntityByMetaAlias(metaAlias);
        final SPSSOConfigElement spssoconfig = metaManager.getSPSSOConfig(realm.toString(), spName);
        final boolean needAssertionEncrypted =
                Boolean.parseBoolean(SAML2Utils.getAttributeValueFromSPSSOConfig(spssoconfig,
                                                                                 SAML2Constants.WANT_ASSERTION_ENCRYPTED));
        final boolean needAttributeEncrypted =
                SPACSUtils.getNeedAttributeEncrypted(needAssertionEncrypted, spssoconfig);
        final Set<PrivateKey> decryptionKeys = KeyUtil.getDecryptionKeys(spssoconfig);
        final List<com.sun.identity.saml2.assertion.Attribute> attrs = SPACSUtils.getAttrs(assertion, needAttributeEncrypted, decryptionKeys);

        final SPAttributeMapper attrMapper = SAML2Utils.getSPAttributeMapper(realm.toString(), spName);

        final Map<String, Set<String>> attrMap;

        try {
            attrMap = attrMapper.getAttributes(attrs, userName, spName, entityName, realm.toString());
        }  catch (SAML2Exception se) {
            return null; //no attributes
        }

        final Map<String, Set<String>> attrMapWithoutDelim = new HashMap<>();

        for (String name : attrMap.keySet()) {
            Set<String> value = attrMap.get(name);
            StringBuilder toStore = new StringBuilder();

            if (CollectionUtils.isNotEmpty(value)) {
                // | is defined as the property value delimiter, cf FMSessionProvider#setProperty
                for (String toAdd : value) {
                    toStore.append(com.sun.identity.shared.StringUtils.getEscapedValue(toAdd))
                           .append(PROPERTY_VALUES_SEPARATOR);
                }
                toStore.deleteCharAt(toStore.length() - 1);
            }
            attrMapWithoutDelim.put(name, Collections.singleton(toStore.toString()));
        }
        return attrMapWithoutDelim;
    }

    /**
     * "Inspired" by the OAuth2 module. We use this cookie to remind us exactly where we are when
     * returning from a remote server as we currently cannot trust the RedirectCallback's authentication
     * framework equiv.
     */
    private void setCookiesForRedirects(final HttpServletRequest request, final HttpServletResponse response) {
        final Set<String> domains = AuthClientUtils.getCookieDomainsForRequest(request);
        final StringBuilder originalUrl = new StringBuilder();
        final String requestedQuery = request.getQueryString();

        final XUIState xuiState = InjectorHolder.getInstance(XUIState.class);

        if (xuiState.isXUIEnabled()) {
            originalUrl.append(request.getContextPath());
        } else {
            originalUrl.append(request.getRequestURI());
        }

        if (StringUtils.isNotEmpty(realm.toString())) {
            originalUrl.append("?realm=").append(urlEncodeQueryParameterNameOrValue(realm.toString()));
        }

        if (requestedQuery != null) {
            originalUrl.append(originalUrl.indexOf("?") == -1 ? '?' : '&');
            originalUrl.append(requestedQuery);
        }

        // Set the return URL Cookie
        for (String domain : domains) {
            CookieUtils.addCookieToResponse(response,
                                            CookieUtils.newCookie("authenticationStep", originalUrl.toString(), "/", domain));
        }
    }

    /**
     * Clears out the cookie from the user agent so we don't leave detritus.
     */
    private void removeCookiesForRedirects(final HttpServletRequest request, final HttpServletResponse response) {
        final Set<String> domains = AuthClientUtils.getCookieDomainsForRequest(request);

        // Set the return URL Cookie
        for (String domain : domains) {
            CookieUtils.addCookieToResponse(response, CookieUtils
                    .newCookie("authenticationStep", "", 0, "/", domain));
        }
    }

    private boolean shouldPersistNameID(String spEntityId) throws SAML2Exception {
        final DefaultLibrarySPAccountMapper spAccountMapper = new DefaultLibrarySPAccountMapper();
        final String spEntityID = SPSSOFederate.getSPEntityId(metaAlias);
        final IDPSSODescriptorType idpsso = SPSSOFederate.getIDPSSOForAuthnReq(realm.toString(), entityName);
        final SPSSODescriptorType spsso = SPSSOFederate.getSPSSOForAuthnReq(realm.toString(), spEntityID);

        nameIDFormat = SAML2Utils.verifyNameIDFormat(nameIDFormat, spsso, idpsso);
        isTransient = SAML2Constants.NAMEID_TRANSIENT_FORMAT.equals(nameIDFormat);
        boolean ignoreProfile = SAML2PluginsUtils.isIgnoredProfile(null, realm.toString());

        return !isTransient && !ignoreProfile
                && spAccountMapper.shouldPersistNameIDFormat(realm.toString(), spEntityId, entityName, nameIDFormat);
    }

    /**
     * Reads the authenticating user's SAML2 NameId from the stored map. Decrypts if necessary.
     */
    private NameID getNameId() throws SAML2Exception, AuthLoginException {
        final EncryptedID encId = assertionSubject.getEncryptedID();
        final String spName = metaManager.getEntityByMetaAlias(metaAlias);
        final SPSSOConfigElement spssoconfig = metaManager.getSPSSOConfig(realm.toString(), spName);
        final Set<PrivateKey> decryptionKeys = KeyUtil.getDecryptionKeys(spssoconfig);

        NameID nameId = assertionSubject.getNameID();

        if (encId != null) {
            nameId = encId.decrypt(decryptionKeys);
        }
        return nameId;
    }

    public enum AuthComparision {
        BETTER,
        EXACT,
        MAXIMUM,
        MINIMUM
    }

    public enum RequestBinding {
        HTTP_REDIRECT {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
            }
        },
        HTTP_POST {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            }
        },
    }

    public enum Binding {
        HTTP_ARTIFACT,
        HTTP_POST
    }
}
