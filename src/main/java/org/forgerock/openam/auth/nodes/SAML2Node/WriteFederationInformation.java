package org.forgerock.openam.auth.nodes.SAML2Node;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.USER_INFO_SHARED_STATE_KEY;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.google.inject.Inject;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.saml2.common.AccountUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
        configClass      = WriteFederationInformation.Config.class)
public class WriteFederationInformation extends SingleOutcomeNode {

    private CoreWrapper coreWrapper;

    /**
     * Node configuration.
     */
    public interface Config {

    }

    @Inject
    public WriteFederationInformation(CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;

        if (!sharedState.isDefined(USER_INFO_SHARED_STATE_KEY)) {
            throw new NodeProcessException("No user information has been found in the shared state. You must call a "
                                                   + "node that sets this information first");
        }
        JsonValue attributes = context.sharedState.get(USER_INFO_SHARED_STATE_KEY).get("attributes");

        String infoAttribute = AccountUtils.getNameIDInfoAttribute();
        String infoKeyAttribute = AccountUtils.getNameIDInfoKeyAttribute();

        if (!attributes.isDefined(infoAttribute)) {
            throw new NodeProcessException(AccountUtils.getNameIDInfoAttribute() + " is not defined in shared state. " +
                                                   "You must first call a node that sets this information first");
        }

        if (!attributes.isDefined(infoKeyAttribute)) {
            throw new NodeProcessException(AccountUtils.getNameIDInfoAttribute() + " is not defined in shared state. " +
                                                   "You must first call a node that sets this information first");
        }

        AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(),
                                                           context.sharedState.get(REALM).asString());

        String infoAttributeValue = attributes.get(infoAttribute).get(0).asString();
        String infoKeyAttributeValue = attributes.get(infoKeyAttribute).get(0).asString();

        //Create payload that will be saved to profile
        Map<String, Set<String>> map = new HashMap<String, Set<String>>() {{
            put(infoAttribute, Collections.singleton(infoAttributeValue));
            put(infoKeyAttribute, Collections.singleton(infoKeyAttributeValue));
        }};

        //Try and save against the user profile
        try {
            userIdentity.setAttributes(map);
            userIdentity.store();

        } catch (IdRepoException | SSOException e) {
            throw new NodeProcessException(e);
        }

        return goToNext().build();
    }
}
