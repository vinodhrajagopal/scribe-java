package org.scribe.extractors;

import com.google.gson.Gson;

import org.scribe.exceptions.OAuthException;
import org.scribe.model.Token;
import org.scribe.utils.Preconditions;

public class GsonAccessTokenExtractor implements AccessTokenExtractor
{

  @Override
  public Token extract(String response)
  {
    Preconditions.checkEmptyString(response, "Cannot extract a token from a null or empty String");
    JSonResponse jsonResponse = new Gson().fromJson(response, JSonResponse.class);
    if(jsonResponse.access_token != null)
    {
      return new Token(jsonResponse.access_token, "", response);
    }
    else
    {
      throw new OAuthException("Cannot extract an acces token. Response was: " + response);
    }
  }

  private static class JSonResponse {
    public String access_token;
  }
}

