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
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.AbstractSocialAuthLoginNode;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.authentication.modules.oauth2.OAuthUtil;
import org.forgerock.openam.authentication.modules.saml2.SAML2Proxy;
import org.forgerock.openam.authentication.modules.saml2.SAML2ResponseData;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.federation.saml2.SAML2TokenRepositoryException;
import org.forgerock.openam.saml2.SAML2Store;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.xui.XUIState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.client.AuthClientUtils;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.RedirectCallback;
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
import com.sun.identity.saml2.jaxb.metadata.EndpointType;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorType;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorType;
import com.sun.identity.saml2.key.KeyUtil;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.plugins.DefaultLibrarySPAccountMapper;
import com.sun.identity.saml2.plugins.SAML2PluginsUtils;
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
    private SocialOAuth2Helper authModuleHelper;


    private static final String MAIL_KEY_MAPPING = "mail";







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
                      SocialOAuth2Helper authModuleHelper) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
        this.coreWrapper = coreWrapper;
        this.authModuleHelper = authModuleHelper;


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

        final HttpServletRequest request = null;
        final HttpServletResponse response = null;

        //TODO Uncomment once I have access to request
//        if (null == request) {
//            throw new NodeProcessException("Unable to login without http request.  Programmatic login is not " +
//                                                    "supported.");
//
//        }
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
            SAML2Utils.debug.message("SAML2 :: initiateSAMLLoginAtIDP() reqBinding is null using endpoint  binding: {}",
                                     endPoint.getBinding());
            reqBinding = endPoint.getBinding();
            if (reqBinding == null) {
                throw new SAML2Exception(SAML2Utils.bundle.getString("UnableTofindBinding"));
            }
        }

        String ssoURL = endPoint.getLocation();
        SAML2Utils.debug.message("SAML2 :: initiateSAMLLoginAtIDP()  ssoURL : {}", ssoURL);

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
        //TODO Uncomment when we have request and response
//        setCookiesForRedirects(request, response);

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

        //TODO uncomment when we have request and response
//        removeCookiesForRedirects(request, response);

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

        final String username;
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

        try { //you're already linked or we auto looked up user
            username = SPACSUtils
                    .getPrincipalWithoutLogin(assertionSubject, authnAssertion, realm.toString(), spName, metaManager,
                                              entityName, storageKey);
            //TODO Need to figure out how to handle dynamic profile scenarios
//            if (SAML2PluginsUtils.isDynamicProfile(realm.toString())) {
            if (true) {
                String spEntityId = SPSSOFederate.getSPEntityId(metaAlias);
                if (shouldPersistNameID(spEntityId)) {
                    NameIDInfo info = new NameIDInfo(spEntityId, entityName, getNameId(), SAML2Constants.SP_ROLE,
                                                     false);

                    // Setup attributes in shared state so that we can leverage Provision Dynamic Account Node and
                    // Provision IDM Account Node to create user profiles
                    Map<String, Set<String>> attributes = AccountUtils.convertToAttributes(info, null);
                    Map<String, Set<String>> userNames = Collections.singletonMap("uid",
                                                                                  Collections.singleton(username));
                    Optional<String> user = authModuleHelper.userExistsInTheDataStore(
                            context.sharedState.get("realm").asString(),
                            OAuthUtil.instantiateAccountProvider("org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider"), userNames);
                    if (user.isPresent()) {
                        return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.ACCOUNT_EXISTS.name())
                                     .replaceSharedState(sharedState);
                    }
                    sharedState.put(USER_INFO_SHARED_STATE_KEY, json(object(
                            field(ATTRIBUTES_SHARED_STATE_KEY, convertToMapOfList(attributes)),
                            field(USER_NAMES_SHARED_STATE_KEY, convertToMapOfList(userNames)))));

                    if (attributes.get(MAIL_KEY_MAPPING) != null) {
                        sharedState.put(EMAIL_ADDRESS, attributes.get(MAIL_KEY_MAPPING).stream().findAny().get());
                    } else {
                        logger.debug("Unable to ascertain email address because the information is not available. "
                                             +
                                             "It's possible you need to add a scope or that the configured provider does not have this "
                                             + "information");
                    }
                }
            }
        } catch (SAML2Exception e) {
            processError("SAML2.handleReturnFromRedirect : Unable to perform user lookup.", null);
        }
        //TODO Handle local chain linking
//        if (StringUtils.isBlank(localChain)) {
//            processError(bundle.getString("localLinkError"), "SAML2 :: handleReturnFromRedirect() : "
//                    + "Unable to perform local linking - local auth chain not found.");
//        }

        //generate a sub-login context, owned by this module, and start login sequence to it
//        authenticationContext = new AuthContext(realm);
//        authenticationContext.login(AuthContext.IndexType.SERVICE, localChain, null, null, null, null);
//
//        return injectCallbacks(null, state);
        return Action.goTo(AbstractSocialAuthLoginNode.SocialAuthOutcome.NO_ACCOUNT.name())
                     .replaceSharedState(sharedState);
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
     * Generates the redirect from SAML2 auth module to IDP as GET.
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
    private Action.ActionBuilder setSessionProperties(Assertion assertion, NameID nameId, String userName)
            throws AuthLoginException, SAML2Exception {
        //if we support single logout sp inititated from the auth module's resulting session
        Action.ActionBuilder actionBuilder = Action.goTo("true");
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

//    /**
//     * Performs the functions of linking attribute values that have been received from the assertion
//     * by building them into appropriate strings and asking the auth service to migrate them into session
//     * properties once authentication is completed.
//     */
//    private void linkAttributeValues(Assertion assertion, String userName)
//            throws AuthLoginException, SAML2Exception {
//
//        final String spName = metaManager.getEntityByMetaAlias(metaAlias);
//        final SPSSOConfigElement spssoconfig = metaManager.getSPSSOConfig(realm.toString(), spName);
//        final boolean needAssertionEncrypted =
//                Boolean.parseBoolean(SAML2Utils.getAttributeValueFromSPSSOConfig(spssoconfig,
//                                                                                 SAML2Constants.WANT_ASSERTION_ENCRYPTED));
//        final boolean needAttributeEncrypted =
//                SPACSUtils.getNeedAttributeEncrypted(needAssertionEncrypted, spssoconfig);
//        final Set<PrivateKey> decryptionKeys = KeyUtil.getDecryptionKeys(spssoconfig);
//        final List<com.sun.identity.saml2.assertion.Attribute> attrs = SPACSUtils.getAttrs(assertion, needAttributeEncrypted, decryptionKeys);
//
//        final SPAttributeMapper attrMapper = SAML2Utils.getSPAttributeMapper(realm, spName);
//
//        final Map<String, Set<String>> attrMap;
//
//        try {
//            attrMap = attrMapper.getAttributes(attrs, userName, spName, entityName, realm);
//        }  catch (SAML2Exception se) {
//            return; //no attributes
//        }
//
//        setUserAttributes(attrMap);
//
//        if (assertion.getAdvice() != null) {
//            List<String> creds = assertion.getAdvice().getAdditionalInfo();
//            attrMap.put(SAML2Constants.DISCOVERY_BOOTSTRAP_CREDENTIALS, new HashSet<>(creds));
//        }
//
//        for (String name : attrMap.keySet()) {
//            Set<String> value = attrMap.get(name);
//            StringBuilder toStore = new StringBuilder();
//
//            if (CollectionUtils.isNotEmpty(value)) {
//                // | is defined as the property value delimiter, cf FMSessionProvider#setProperty
//                for (String toAdd : value) {
//                    toStore.append(com.sun.identity.shared.StringUtils.getEscapedValue(toAdd))
//                           .append(PROPERTY_VALUES_SEPARATOR);
//                }
//                toStore.deleteCharAt(toStore.length() - 1);
//            }
//            setUserSessionProperty(name, toStore.toString());
////        }
//    }

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

    private boolean shouldPersistNameID(String spEntityId) throws SAML2Exception {
        final DefaultLibrarySPAccountMapper spAccountMapper = new DefaultLibrarySPAccountMapper();
        final String spEntityID = SPSSOFederate.getSPEntityId(metaAlias);
        final IDPSSODescriptorType idpsso = SPSSOFederate.getIDPSSOForAuthnReq(realm.toString(), entityName);
        final SPSSODescriptorType spsso = SPSSOFederate.getSPSSOForAuthnReq(realm.toString(), spEntityID);

        nameIDFormat = SAML2Utils.verifyNameIDFormat(nameIDFormat, spsso, idpsso);
        isTransient = SAML2Constants.NAMEID_TRANSIENT_FORMAT.equals(nameIDFormat);

        //TODO Figure out how to get SSO Token within node framework
//        Object session = null;
//        try {
//            session = getLoginState("shouldPersistNameID").getSSOToken();
//        } catch (SSOException | AuthLoginException ssoe) {
//            if (DEBUG.messageEnabled()) {
//                DEBUG.message("SAML2 :: failed to get user's SSOToken.");
//            }
//        }
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
