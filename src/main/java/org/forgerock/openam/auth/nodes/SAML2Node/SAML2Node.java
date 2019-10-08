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

import static com.sun.identity.saml2.common.SAML2Constants.IDPENTITYID;
import static java.lang.Boolean.parseBoolean;
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

import org.apache.commons.collections.MapUtils;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.AbstractSocialAuthLoginNode;
import org.forgerock.openam.authentication.modules.saml2.SAML2Proxy;
import org.forgerock.openam.authentication.modules.saml2.SAML2ResponseData;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.federation.saml2.SAML2TokenRepositoryException;
import org.forgerock.openam.saml2.SAML2Store;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.xui.XUIState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.client.AuthClientUtils;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
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
import com.sun.identity.sm.RequiredValueValidator;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    private static final String CACHE_KEY = "cacheKey";
    private static final String IS_TRANSIENT = "isTransient";
    private static final String REQUEST_ID = "requestId";

    private static final String BUNDLE_NAME = "amAuthSAML2";
    private static final String AUTH_COMPARISON = "AuthComparison";
    private static final String JSON_CONTENT = "jsonContent";
    private ResourceBundle bundle = null;



    private final Logger logger = LoggerFactory.getLogger(SAML2Node.class);
    private Map<String, List<String>> params = new HashMap<>();

    private final Config config;
    private final String realm;

    private String nameIDFormat;
    private final String entityName;
    private final String metaAlias;
    private String reqBinding;
    private Binding binding;
    private final boolean singleLogoutEnabled;
    private final String sloRelayState;
    private final SAML2MetaManager metaManager;
    private AuthnRequest authnRequest;
    private String storageKey;
    private Assertion authnAssertion;
    private String sessionIndex;
    private ResponseInfo respInfo;
    private IDPSSODescriptorType idpsso;
    private SPSSODescriptorType spsso;
    private String spEntityID;
    private String spName;
    private boolean isTransient;


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
        default AuthComparision authComparision() { return AuthComparision.EXACT; }

        @Attribute(order = 500)
        default String authnContextClassRef() { return ""; }

        @Attribute(order = 600)
        default String authNContextDeclRef() { return ""; }

        @Attribute(order = 700)
        default RequestBinding reqBinding() { return RequestBinding.HTTP_REDIRECT; }

        @Attribute(order = 800)
        default Binding binding() { return Binding.HTTP_ARTIFACT; }

        @Attribute(order = 900)
        default boolean forceAuthn() { return false; }

        @Attribute(order = 1000)
        default boolean isPassive() { return false; }

        @Attribute(order = 1100)
        default NameIdFormat nameIdFormat() { return NameIdFormat.PERSISTENT; }

        @Attribute(order = 1200)
        default boolean sloEnabled() { return false; }

        @Attribute(order = 1500)
        default String sloRelay() { return "http://"; }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     */
    @Inject
    public SAML2Node(@Assisted Config config, @Assisted Realm realm) {
        this.config = config;
        this.realm = realm.toString();

        entityName = config.entityName();
        metaAlias = config.metaAlias();
        reqBinding = config.reqBinding().toString();
        binding = config.binding();
        singleLogoutEnabled = config.sloEnabled();
        sloRelayState = config.sloRelay();
        metaManager = SAML2Utils.getSAML2MetaManager();
        params.put(SAML2Constants.IDPENTITYID, Collections.singletonList(config.entityName()));
        params.put(SAML2Constants.ALLOWCREATE, Collections.singletonList(Boolean.toString(config.allowCreate())));
        params.put(AUTH_COMPARISON, Collections.singletonList(config.authComparision().name().toLowerCase()));
        if (StringUtils.isNotEmpty(config.authnContextClassRef())) {
            params.put(SAML2Constants.AUTH_CONTEXT_CLASS_REF, Collections.singletonList(config.authnContextClassRef()));

        }
        if (StringUtils.isNotEmpty(config.authNContextDeclRef())) {
            params.put(SAML2Constants.AUTH_CONTEXT_DECL_REF, Collections.singletonList(config.authNContextDeclRef()));
        }
        params.put(SAML2Constants.BINDING,
                    Collections.singletonList(config.binding().toString()
                                                    .substring(config.binding().toString().lastIndexOf(":") + 1)));
        params.put(SAML2Constants.FORCEAUTHN, Collections.singletonList(Boolean.toString(config.forceAuthn())));
        params.put(SAML2Constants.ISPASSIVE, Collections.singletonList(Boolean.toString(config.isPassive())));
        params.put(SAML2Constants.NAMEID_POLICY_FORMAT, Collections.singletonList(config.nameIdFormat().toString()));
        params.put(SAML2Constants.REQ_BINDING, Collections.singletonList(config.reqBinding().toString()));



    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        this.bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE_NAME, getClass().getClassLoader());
        final HttpServletRequest request = context.request.servletRequest;
        final HttpServletResponse response = context.request.servletResponse;

        if (null == request) {
            throw new NodeProcessException("Unable to login without http request. Programmatic login is not supported.");
        }
        try {
            spName = metaManager.getEntityByMetaAlias(metaAlias);
            spEntityID = SPSSOFederate.getSPEntityId(metaAlias);
            idpsso = SPSSOFederate.getIDPSSOForAuthnReq(realm, entityName);
            spsso = SPSSOFederate.getSPSSOForAuthnReq(realm, spEntityID);
            nameIDFormat = SAML2Utils.verifyNameIDFormat(config.nameIdFormat().toString(), spsso, idpsso);
            if (request.getParameterMap().containsKey("responsekey")) {
                return handleReturnFromRedirect(context, request, spName, response).build();
            }
            return Action.send(initiateSAMLLoginAtIDP(request, response)).build();
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }

    }

    /**
     * Performs similar to SPSSOFederate.initiateAuthnRequest by returning to the next auth stage
     * with a redirect (either GET or POST depending on the config) which triggers remote IdP authentication.
     */
    private Callback initiateSAMLLoginAtIDP(HttpServletRequest request, HttpServletResponse response)
            throws SAML2Exception, NodeProcessException {

        if (idpsso == null || spsso == null) {
            throw new NodeProcessException("Failed to load SAML2 Configuration.");
        }

        final EndpointType endPoint = SPSSOFederate
                .getSingleSignOnServiceEndpoint(idpsso.getSingleSignOnService(), reqBinding);

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

        final Map<String, Collection<String>> spConfigAttrsMap = SPSSOFederate.getAttrsMapForAuthnReq(realm,
                                                                                                       spEntityID);


        authnRequest = SPSSOFederate.createAuthnRequest(request, response, realm, spEntityID, entityName, params,
                                                        spConfigAttrsMap,
                                                        SPSSOFederate.getExtensionsList(spEntityID,
                                                        String.valueOf(realm)), spsso, idpsso, ssoURL, false);

        final AuthnRequestInfo reqInfo = new AuthnRequestInfo(request, response, realm, spEntityID, null,
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
            throws NodeProcessException, SAML2Exception {

        removeCookiesForRedirects(request, response);

        if (parseBoolean(request.getParameter(SAML2Proxy.ERROR_PARAM_KEY))) {
            handleRedirectError(request);
        }

        if (request.getParameter(JSON_CONTENT) != null) {
            storageKey = JsonValueBuilder.toJsonValue(request.getParameter(JSON_CONTENT)).get("responsekey").asString();
        } else {
            storageKey = request.getParameter(SAML2Proxy.RESPONSE_KEY);
        }

        SAML2ResponseData data = null;

        if (!StringUtils.isBlank(storageKey)) {
            data = (SAML2ResponseData) SAML2Store.getTokenFromStore(storageKey);

            if (data == null) {
                if (SAML2FailoverUtils.isSAML2FailoverEnabled()) {
                    try {
                        data = (SAML2ResponseData) SAML2FailoverUtils.retrieveSAML2Token(storageKey);
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

        Subject assertionSubject = data.getSubject();
        authnAssertion = data.getAssertion();
        sessionIndex = data.getSessionIndex();
        respInfo = data.getResponseInfo();
        JsonValue sharedState = context.sharedState;

        final EncryptedID encId = assertionSubject.getEncryptedID();
        final SPSSOConfigElement spssoConfig;
        final SPAccountMapper acctMapper;
        spssoConfig = metaManager.getSPSSOConfig(realm, spName);
        acctMapper = SAML2Utils.getSPAccountMapper(realm, spName);

        Set<PrivateKey> decryptionKeys = KeyUtil.getDecryptionKeys(spssoConfig);
        boolean needNameIDEncrypted = false;
        NameID nameId = assertionSubject.getNameID();

        boolean needAssertionEncrypted = parseBoolean(SAML2Utils.getAttributeValueFromSPSSOConfig(spssoConfig,
                                                                          SAML2Constants.WANT_ASSERTION_ENCRYPTED));
        if (!needAssertionEncrypted) {
            String idEncryptedStr =
                    SAML2Utils.getAttributeValueFromSPSSOConfig(spssoConfig, SAML2Constants.WANT_NAMEID_ENCRYPTED);
            needNameIDEncrypted = parseBoolean(idEncryptedStr);
        }

        if (needNameIDEncrypted && encId == null) {
            throw new NodeProcessException(SAML2Utils.bundle.getString("nameIDNotEncrypted"));
        }
        if (encId != null) {
                nameId = encId.decrypt(decryptionKeys);
        }

        SPSSODescriptorType spDesc = null;
        try {
            spDesc = metaManager.getSPSSODescriptor(realm, spName);
        } catch (SAML2MetaException ex) {
            logger.error("Unable to read SPSSODescription", ex);
        }

        if (spDesc == null) {
            throw new NodeProcessException(SAML2Utils.bundle.getString("metaDataError"));
        }

        if (nameIDFormat != null) {
            List spNameIDFormatList = spDesc.getNameIDFormat();

            if (CollectionUtils.isNotEmpty(spNameIDFormatList) && !spNameIDFormatList.contains(nameIDFormat)) {
                throw new NodeProcessException("Unsupported NameIDFormat SP: " + nameIDFormat);
            }
        }

        isTransient = SAML2Constants.NAMEID_TRANSIENT_FORMAT.equals(nameIDFormat);
        final boolean disableNameIDPersistence = !acctMapper.shouldPersistNameIDFormat(realm, spName,
                                                                                       entityName, nameIDFormat);
        final boolean persistNameId = !isTransient && !disableNameIDPersistence;

        Map nameIdKeyMap = SAML2Utils.getNameIDKeyMap(nameId, spName, entityName, realm, SAML2Constants.SP_ROLE);

        String dn;
        //If nameID format isn't transient and we should should persist name ID returns true, then look for user via
        // nameID
        if (persistNameId) {
            try {
                dn = SAML2Utils.getDataStoreProvider().getUserID(realm, nameIdKeyMap);
                if (StringUtils.isNotEmpty(dn)) {
                    return setSessionProperties(Action
                        .goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                        .replaceSharedState(sharedState.put(SharedStateConstants.USERNAME,
                                                            new AMIdentity(null, dn).getName())), nameId);
                }
            } catch (DataStoreProviderException | IdRepoException e) {
                throw new NodeProcessException(e);
            }
        }

        // If we haven't found the user yet, use the configured account mapper to find the user based on auto
        // federation or transient user configuration
        dn = acctMapper.getIdentity(authnAssertion, spName, realm);

        //If this is the transient user being returned from the account mapper, return it
        if (StringUtils.isNotEmpty(dn) && StringUtils.isEqualTo(SAML2Utils.getAttributeValueFromSPSSOConfig(spssoConfig,
                                                                      SAML2Constants.TRANSIENT_FED_USER), dn)) {
            return setSessionProperties(Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                         .replaceSharedState(sharedState.put(SharedStateConstants.USERNAME, dn)), nameId);

        }

        try {
            // See if an AMIdentity Exists (only if this is a DN string that our acctMapper returned)
            String username = new AMIdentity(null, dn).getName();
            if (persistNameId) {
                persistFederationInfo(spName, nameId, dn);
            }
            return setSessionProperties(Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                         .replaceSharedState(sharedState.put(SharedStateConstants.USERNAME, username)), nameId);
        } catch (IdRepoException e) {
            // If it wasn't then setup attributes and go to No Account outcome.
            return setSessionProperties(Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.NO_ACCOUNT.name())
                         .replaceSharedState(setupAttributes(spssoConfig, decryptionKeys, nameId, spName, sharedState, dn,
                                                             persistNameId, needAssertionEncrypted)), nameId);
        }
    }

    private void persistFederationInfo(String spName, NameID nameId, String username) throws SAML2Exception {

        final NameIDInfo info;
        final String affiID = nameId.getSPNameQualifier();
        boolean isDualRole = SAML2Utils.isDualRole(spName, realm);
        AffiliationDescriptorType affiDesc = null;


        if (affiID != null && !affiID.isEmpty()) {
            affiDesc = metaManager.getAffiliationDescriptor(realm, affiID);
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
    }

    private JsonValue setupAttributes(SPSSOConfigElement spssoConfig,
                                      Set<PrivateKey> decryptionKeys, NameID nameID,
                                      String spName,
                                      JsonValue sharedState, String username, boolean persistNameId,
                                      boolean needAssertionEncrypted)
            throws NodeProcessException {
        Map<String, Set<String>> attributes;
        try {
            attributes = linkAttributeValues(spssoConfig, decryptionKeys, authnAssertion, username, needAssertionEncrypted);
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }
        NameIDInfo info;
        try {
            if (persistNameId) {
                info = new NameIDInfo(spName, entityName, nameID, SAML2Constants.SP_ROLE,
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
                                                                  Collections.singleton(username)))))));

        if (attributes.get(MAIL_KEY_MAPPING) != null) {
            sharedState.put(EMAIL_ADDRESS, attributes.get(MAIL_KEY_MAPPING).stream().findAny().get());
        } else {
            logger.debug("Unable to ascertain email address because the information is not available. It's possible " +
                                 "you need to add a scope or that the configured provider does not have this " +
                                 "information");
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
                                               final RedirectCallback redirectCallback) {
        final Map<String, String> postData = new HashMap<>();
        postData.put(SAML2Constants.SAML_REQUEST, postMsg);
        final RedirectCallback rcNew = new RedirectCallback(ssoURL, postData, "POST",
                                                            redirectCallback.getStatusParameter(),
                                                            redirectCallback.getRedirectBackUrlCookieName());
        rcNew.setTrackingCookie(true);
        return rcNew;
    }

    /**
     * Generates the redirect from SAML2 auth node to IDP as GET.
     */
    private RedirectCallback configureGetRedirectCallback(final String redirectUrl, RedirectCallback redirectCallback) {
        final RedirectCallback rcNew = new RedirectCallback(redirectUrl, null, "GET",
                                                            redirectCallback.getStatusParameter(),
                                                            redirectCallback.getRedirectBackUrlCookieName());
        rcNew.setRedirectData(rcNew.getRedirectData());
        rcNew.setTrackingCookie(true);
        return rcNew;
    }

    /**
     * Writes out an error debug (if a throwable and debug message are provided) and returns a user-facing
     * error page.
     */
    private void processError(String headerMessage, String debugMessage,
                             Object... messageParameters) throws NodeProcessException {
        if (null != debugMessage) {
            logger.error(debugMessage, messageParameters);
        }
        throw new NodeProcessException(headerMessage);
    }

    /**
     * Grab error code/message and display to user via processError.
     */
    private void handleRedirectError(HttpServletRequest request) throws NodeProcessException {
        final String errorCode = request.getParameter(SAML2Proxy.ERROR_CODE_PARAM_KEY);
        final String errorMessage = request.getParameter(SAML2Proxy.ERROR_MESSAGE_PARAM_KEY);

        if (StringUtils.isNotEmpty(errorMessage)) {
            processError(errorMessage, "SAML2 :: handleReturnFromRedirect() : "
                    + "error forwarded from saml2AuthAssertionConsumer.jsp.  Error code - {}. "
                    + "Error message - {}", String.valueOf(errorCode), errorMessage);
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

    /**
     * Adds information necessary for the session to be federated completely (if attributes are being
     * drawn in, and to configure ready for SLO).
     */
    private Action.ActionBuilder setSessionProperties(Action.ActionBuilder actionBuilder, NameID nameId)
            throws NodeProcessException {
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
        try {
            actionBuilder.putSessionProperty(SAML2Constants.SPENTITYID, SPSSOFederate.getSPEntityId(metaAlias));
            actionBuilder.putSessionProperty(SAML2Constants.NAMEID, nameId.toXMLString(true, true));
        } catch (SAML2Exception e) {
            throw new NodeProcessException(e);
        }
        actionBuilder.putSessionProperty(IDPENTITYID, entityName);
        actionBuilder.putSessionProperty(SAML2Constants.METAALIAS, metaAlias);
        actionBuilder.putSessionProperty(SAML2Constants.REQ_BINDING, reqBinding);
        actionBuilder.putSessionProperty(IS_TRANSIENT, Boolean.toString(isTransient));
        actionBuilder.putSessionProperty(REQUEST_ID, respInfo.getResponse().getInResponseTo());
        actionBuilder.putSessionProperty(SAML2Constants.BINDING, binding.toString());
        actionBuilder.putSessionProperty(CACHE_KEY, storageKey);
        return actionBuilder;
    }

    /**
     * Performs the functions of linking attribute values that have been received from the assertion
     * by building them into appropriate strings and asking the auth service to migrate them into session
     * properties once authentication is completed.
     */
    private Map<String, Set<String>> linkAttributeValues(SPSSOConfigElement spssoConfig,
                                                         Set<PrivateKey> decryptionKeys,
                                                         Assertion assertion,
                                                         String userName, boolean needAssertionEncrypted)
            throws SAML2Exception, NodeProcessException {
        final List<com.sun.identity.saml2.assertion.Attribute> attrs = SPACSUtils.getAttrs(assertion,
                            SPACSUtils.getNeedAttributeEncrypted(needAssertionEncrypted, spssoConfig), decryptionKeys);

        final SPAttributeMapper attrMapper = SAML2Utils.getSPAttributeMapper(realm, spName);

        final Map<String, Set<String>> attrMap;

        try {
            attrMap = attrMapper.getAttributes(attrs, userName, spName, entityName, realm);
        }  catch (SAML2Exception se) {
            return null; //no attributes
        }

        if (MapUtils.isEmpty(attrMap)) {
            throw new NodeProcessException("SAML Attribute Map is empty for SP:" + spEntityID);
        }

        final Map<String, Set<String>> attrMapWithoutDelimiter = new HashMap<>();

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
            attrMapWithoutDelimiter.put(name, Collections.singleton(toStore.toString()));
        }
        return attrMapWithoutDelimiter;
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

        if (StringUtils.isNotEmpty(realm)) {
            originalUrl.append("?realm=").append(urlEncodeQueryParameterNameOrValue(realm));
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
        HTTP_ARTIFACT{
            @Override
            public java.lang.String toString() {
                return "HTTP-Artifact";
            }
        },
        HTTP_POST{
            @Override
            public java.lang.String toString() {
                return "HTTP-POST";
            }
        }
    }

    public enum NameIdFormat {
        PERSISTENT {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
            }
        },
        TRANSIENT {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            }
        },
        UNSPECIFIED_SAML1 {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
            }
        },
        UNSPECIFIED_SAML2 {
            @Override
            public java.lang.String toString() {
                return "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
            }
        }
    }
}
