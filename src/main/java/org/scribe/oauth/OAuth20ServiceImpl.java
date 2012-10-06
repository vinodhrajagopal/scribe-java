package org.scribe.oauth;

import org.scribe.builder.api.*;
import org.scribe.model.*;

import java.util.HashMap;
import java.util.Map;

public class OAuth20ServiceImpl implements OAuthService
{
  private static final String VERSION = "2.0";
  
  private final DefaultApi20 api;
  private final OAuthConfig config;
  
  /**
   * Default constructor
   * 
   * @param api OAuth2.0 api information
   * @param config OAuth 2.0 configuration param object
   */
  public OAuth20ServiceImpl(DefaultApi20 api, OAuthConfig config)
  {
    this.api = api;
    this.config = config;
  }

  /**
   * {@inheritDoc}
   */
  public Token getAccessToken(Token requestToken, Verifier verifier)
  {
    OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
    Map<String,String> parameterMap = createParameterMap(verifier);
    if (api.getAccessTokenVerb().equals(Verb.POST)) {
      request.addBodyParameters(parameterMap);
    } else {
      request.addQuerystringParameters(parameterMap);
    }
    Response response = request.send();
    return api.getAccessTokenExtractor().extract(response.getBody());
  }
  
  private Map<String,String> createParameterMap(Verifier verifier) {
    Map<String,String> paramList = new HashMap<String,String>();
    paramList.put(OAuthConstants.CLIENT_ID, config.getApiKey());
    paramList.put(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
    paramList.put(OAuthConstants.CODE, verifier.getValue());
    paramList.put(OAuthConstants.REDIRECT_URI, config.getCallback());
    paramList.put(OAuthConstants.GRANT_TYPE, OAuthConstants.AUTHORIZATION_CODE);
    if(config.hasScope()) paramList.put(OAuthConstants.SCOPE, config.getScope());
    return paramList;
  }

  /**
   * {@inheritDoc}
   */
  public Token getRequestToken()
  {
    throw new UnsupportedOperationException("Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
  }

  /**
   * {@inheritDoc}
   */
  public String getVersion()
  {
    return VERSION;
  }

  /**
   * {@inheritDoc}
   */
  public void signRequest(Token accessToken, OAuthRequest request)
  {
    request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
  }

  /**
   * {@inheritDoc}
   */
  public String getAuthorizationUrl(Token requestToken)
  {
    return api.getAuthorizationUrl(config);
  }

}
