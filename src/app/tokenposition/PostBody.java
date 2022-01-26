package app.tokenposition;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.Config;
import app.helpers.KeyValuePair;
import app.helpers.Output;
import app.helpers.TokenCheck;

public class PostBody extends ITokenPosition {

  private String token;
  private boolean found = false;
  private String body;


  public PostBody(List<String> headersP, String bodyP) {
    body = bodyP;
  }

  @Override
  public boolean positionFound() {
    if (isRequest) {
      KeyValuePair postJWT = getJWTFromPostBody();
      if (postJWT != null) {
        found = true;
        token = postJWT.getValue();
        return true;
      }
    }
    return false;
  }

  public KeyValuePair getJWTFromPostBody() {
    int from = 0;
    int index = body.contains("&") ? body.indexOf("&") : body.length();
    int parameterCount = StringUtils.countMatches(body, "&") + 1;

    List<KeyValuePair> postParameterList = new ArrayList<>();
    for (int i = 0; i < parameterCount; i++) {
      String parameter = body.substring(from, index);
      parameter = parameter.replace("&", "");

      String[] parameterSplit = parameter.split(Pattern.quote("="));
      if (parameterSplit.length > 1) {
        String name = parameterSplit[0];
        String value = parameterSplit[1];
        postParameterList.add(new KeyValuePair(name, value));
        from = index;
        index = body.indexOf("&", index + 1);
        if (index == -1) {
          index = body.length();
        }
      }
    }
    for (String keyword : Config.tokenKeywords) {
      for (KeyValuePair postParameter : postParameterList) {
        if (keyword.equals(postParameter.getName()) && TokenCheck.isValidJWT(postParameter.getValue())) {
          return postParameter;
        }
      }
    }
    return null;
  }

  @Override
  public String getToken() {
    return found ? token : "";
  }

  @Override
  public byte[] replaceToken(String newToken) {
    body = replaceTokenImpl(newToken, body);
    return getHelpers().buildHttpMessage(getHeaders(), body.getBytes());
  }

  public String replaceTokenImpl(String newToken, String body) {
    boolean replaced = false;
    // we cannot use the location of parameter, as the body might have changed, thus
    // we need to search for it again
    KeyValuePair postJWT = getJWTFromPostBody();
    for (String keyword : Config.tokenKeywords) {
      if (keyword.equals(postJWT.getName())) {
        String toReplace = postJWT.getNameAsParam() + postJWT.getValue();
        body = body.replace(toReplace, postJWT.getNameAsParam() + newToken);
        replaced = true;
      }
    }
    if (!replaced) {
      Output.outputError("Could not replace token in post body.");
    }
    return body;
  }

  @Override
  public String toHTMLString() {
    return "";
  }
}
