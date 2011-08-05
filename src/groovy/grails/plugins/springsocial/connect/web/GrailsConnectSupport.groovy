/* Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugins.springsocial.connect.web

import org.springframework.social.connect.ConnectionFactory
import org.springframework.social.connect.support.OAuth1ConnectionFactory
import org.springframework.social.connect.support.OAuth2ConnectionFactory
import org.springframework.social.connect.web.ConnectSupport
import org.springframework.social.oauth1.OAuth1Operations
import org.springframework.social.oauth1.OAuth1Parameters
import org.springframework.social.oauth1.OAuth1Version
import org.springframework.social.oauth1.OAuthToken
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.context.request.RequestAttributes

class GrailsConnectSupport extends ConnectSupport {
    private static final String OAUTH_TOKEN_ATTRIBUTE = "oauthToken";
    String home

    public String buildOAuthUrl(ConnectionFactory<?> connectionFactory, NativeWebRequest request) {
        if (connectionFactory instanceof OAuth1ConnectionFactory) {
            return buildOAuth1Url((OAuth1ConnectionFactory<?>) connectionFactory, request);
        } else if (connectionFactory instanceof OAuth2ConnectionFactory) {
            return buildOAuth2Url((OAuth2ConnectionFactory<?>) connectionFactory, request);
        } else {
            throw new IllegalArgumentException("ConnectionFactory not supported");
        }
    }


    private String buildOAuth1Url(OAuth1ConnectionFactory<?> connectionFactory, NativeWebRequest request) {
        OAuth1Operations oauthOperations = connectionFactory.getOAuthOperations();
        OAuthToken requestToken;
        String authorizeUrl;
        def providerId = connectionFactory.getProviderId()
        if (oauthOperations.getVersion() == OAuth1Version.CORE_10_REVISION_A) {
            requestToken = oauthOperations.fetchRequestToken(callbackUrl(request, providerId), null);
            authorizeUrl = buildOAuth1Url(oauthOperations, requestToken.getValue(), OAuth1Parameters.NONE);
        } else {
            requestToken = oauthOperations.fetchRequestToken(null, null);
            authorizeUrl = buildOAuth1Url(oauthOperations, requestToken.getValue(), new OAuth1Parameters(callbackUrl(request, providerId)));
        }
        request.setAttribute(OAUTH_TOKEN_ATTRIBUTE, requestToken, RequestAttributes.SCOPE_SESSION);
        return authorizeUrl;
    }

    private String callbackUrl(NativeWebRequest request, String providerId) {
        "${home}ssconnect/${providerId}".toString()
    }

}
