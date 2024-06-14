package app.helpers;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.eclipsesource.json.WriterConfig;

public class Config {

  public static List<String> tokenKeywords = Arrays.asList("id_token", "ID_TOKEN", "access_token", "token");
  public static String highlightColor = "Blue";
  public static String interceptComment = "Contains a JWT";
  public static boolean resetEditor = true;
  public static boolean o365Support = true;
  public static String configName = "config.json";
  public static String configFolderName = ".JWT4B";
  public static String configPath =
      System.getProperty("user.home") + File.separator + configFolderName + File.separator + configName;

/*
  ssh-keygen -t rsa -b 2048 -m PEM -f jwtRS256.key
  # Don't add passphrase
  openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
  cat jwtRS256.key
  cat jwtRS256.key.pub
 */

  public static String cveAttackModePublicKey =
      "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuvBC2RJqGAbPg6HoJaOl\n"
          + "T6L4tMwMzGUI8TptoBlStWe+TfRcuPVfxI1U6g87/7B62768kuU55H8bd3Yd7nBm\n"
          + "mdzuNthAdPDMXlrnIbOywG52iPtHAV1U5Vk5QGuj39aSuLjpBSC4jUJPcdJENpmE\n"
          + "CVX+EeNwZlOEDfbtnpOTMRr/24r1CLSMwp9gtaLnE6NJzh+ycTDgyrWK9OtNA+Uq\n"
          + "zwfNJ9BfE53u9JHJP/nWZopqlNQ26fgPASu8FULa8bmJ3kc0SZFCNvXyjZn7HVCw\n"
          + "Ino/ZEq7oN9tphmAPBwdfQhb2xmD3gYeWrXNP/M+SKisaX1CVwaPPowjCQMbsmfC\n" + "2wIDAQAB\n"
          + "-----END PUBLIC KEY-----";

  public static String cveAttackModePrivateKey =
      "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAuvBC2RJqGAbPg6HoJaOlT6L4tMwMzGUI8TptoBlStWe+TfRc\n"
          + "uPVfxI1U6g87/7B62768kuU55H8bd3Yd7nBmmdzuNthAdPDMXlrnIbOywG52iPtH\n"
          + "AV1U5Vk5QGuj39aSuLjpBSC4jUJPcdJENpmECVX+EeNwZlOEDfbtnpOTMRr/24r1\n"
          + "CLSMwp9gtaLnE6NJzh+ycTDgyrWK9OtNA+UqzwfNJ9BfE53u9JHJP/nWZopqlNQ2\n"
          + "6fgPASu8FULa8bmJ3kc0SZFCNvXyjZn7HVCwIno/ZEq7oN9tphmAPBwdfQhb2xmD\n"
          + "3gYeWrXNP/M+SKisaX1CVwaPPowjCQMbsmfC2wIDAQABAoIBAGtODOEzq8i86BMk\n"
          + "NfCdHgA3iVGmq1YMTPTDWDgFMS/GLDvtH+hfmShnBC4SrpsXv34x32bmw7OArtCE\n"
          + "8atzw8FgSzEaMu2tZ3Jl9bSnxNymy83XhyumWlwIOk/bOcb8EV6NbdyuqqETRi0M\n"
          + "yHEa7+q3/M5h4pwqJmwpqL5U8bHGVGXNEbiA/TneNyXjSn03uPYaKTw4R9EG951A\n"
          + "pCJf4Atba5VIfdZ59fx/6rxCuKjWlvZrklE3Cll/+A0dRN5vBSR+EBYgfedMPepM\n"
          + "6TYDOsQnsy1bFJjy+aE/kwYGgtjuHOlvCpwq90SY3WueXClDfioaJ/1S6QT3q8hf\n"
          + "UHodWxkCgYEA8X6+dybVvBgawxyYZEi1P/KNWC9tr2zdztnkDB4nn97UIJzxmjTh\n"
          + "s81EsX0Mt24DJg36HoX5x1lDHNrR2RvIEPy8vfzTdNVa6KP7E7CWUUcW39nmt/z7\n"
          + "ezlyZa8TVPBE/xvozdZuTAzd0rafUX3Ugqzn17MBshz07/K4Z0iy/C0CgYEAxiqm\n"
          + "J7ul9CmNVvCnQ19tvcO7kY8h9AYIEtrqf9ubiq9W7Ldf9mXIhlG3wr6U3dXuAVVa\n"
          + "4g9zkXr+N7BE4hlQcJpBn5ywtYfqzK1GRy+rfwPgC/JbWEnNDP8oYnZ8R6pkhyOC\n"
          + "zqDqCZPtnmD9Je/ifdmgIkkxQD25ktyCYMhPuCcCgYEAh/MQCkfEfxUay8gnSh1c\n"
          + "W9mSFJjuqJki7TXgmanIKMnqpUl1AZjPjsb56uk45XJ7N0sbCV/m04C+tVnCVPS8\n"
          + "1kNRhar054rMmLbnu5fnp23bxL0Ik39Jm38llXTP7zsrvGnbzzTt9sYvglXorpml\n"
          + "rsLj6ZwOUlTW1tXPVeWpTSkCgYBfAkGpWRlGx8lA/p5i+dTGn5pFPmeb9GxYheba\n"
          + "KDMZudkmIwD6RHBwnatJzk/XT+MNdpvdOGVDQcGyd2t/L33Wjs6ZtOkwD5suSIEi\n"
          + "TiOeAQChGbBb0v5hldAJ7R7GyVXrSMZFRPcQYoERZxTX5HwltHpHFepsD2vykpBb\n"
          + "0I4QDwKBgDRH3RjKJduH2WvHOmQmXqWwtkY7zkLwSysWTW5KvCEUI+4VHMggaQ9Z\n"
          + "YUXuHa8osFZ8ruJzSd0HTrDVuNTb8Q7XADOn4a5AGHu1Bhw996uNCP075dx8IOsl\n"
          + "B6zvMHB8rRW93GfFd08REpsgqSm+AL6iLlZHowC00FFPtLs9e7ci\n" + "-----END RSA PRIVATE KEY-----";


  public static void loadConfig() {

    File configFile = new File(configPath);

    if (!configFile.getParentFile().exists()) {
      Output.output("Config file directory '" + configFolderName + "' does not exist - creating it");
      boolean mkdir = configFile.getParentFile().mkdir();
      if (!mkdir) {
        Output.outputError("Could not create directory '" + configFile.getParentFile().toString() + "'");
      }
    }

    if (!configFile.exists()) {
      Output.output("Config file '" + configPath + "' does not exist - creating it");
      try {
        boolean configFileCreated = configFile.createNewFile();
        if (!configFileCreated) {
          throw new IOException("Create new file failed for config file");
        }
      } catch (IOException e) {
        Output.outputError(
            "Error creating config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause()
                .toString());
        return;
      }
      String defaultConfigJSONRaw = generateDefaultConfigFile();
      try {
        Files.write(Paths.get(configPath), defaultConfigJSONRaw.getBytes());
      } catch (IOException e) {
        Output.outputError(
            "Error writing config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause()
                .toString());
      }
    }

    try {
      String configRaw = new String(Files.readAllBytes(Paths.get(configPath)));
      JsonObject configJO = Json.parse(configRaw).asObject();
     
      JsonArray tokenKeywordsJA = configJO.get("tokenKeywords").asArray();
      tokenKeywords = new ArrayList<>();
      for (JsonValue tokenKeyword : tokenKeywordsJA) {
        tokenKeywords.add(tokenKeyword.asString());
      }

      resetEditor = configJO.getBoolean("resetEditor", true);

      o365Support = configJO.getBoolean("o365Support", true);

      highlightColor = configJO.get("highlightColor").asString();

      // support color names regardless of case
      highlightColor = highlightColor.substring(0, 1).toUpperCase() + highlightColor.substring(1).toLowerCase();

      // 	red, orange, yellow, green, cyan, blue, pink, magenta, gray,or a null String to clear any existing highlight.
      ArrayList<String> allowedColors = new ArrayList<>(
          Arrays.asList("Red", "Orange", "Yellow", "Green", "Cyan", "Blue", "Pink", "Magenta", "Gray", "None"));
      if (!allowedColors.contains(highlightColor)) {
        highlightColor = "None";
        Output.output(
            "Unknown color, only 'Red, Orange, Yellow, Green, Cyan, Blue, Pink, Magenta, Gray, None' is possible - defaulting to None.");
      }

      interceptComment = configJO.get("interceptComment").asString();
      cveAttackModePublicKey = configJO.get("cveAttackModePublicKey").asString();
      cveAttackModePrivateKey = configJO.get("cveAttackModePrivateKey").asString();

    } catch (IOException e) {
      Output.outputError(
          "Error loading config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause()
              .toString());
    }
  }

  private static String generateDefaultConfigFile() {
    JsonObject configJO = new JsonObject();

    JsonArray tokenKeywordsJA = new JsonArray();
    for (String tokenKeyword : tokenKeywords) {
      tokenKeywordsJA.add(tokenKeyword);
    }

    configJO.add("resetEditor", true);
    configJO.add("o365Support", true);
    configJO.add("highlightColor", highlightColor);
    configJO.add("interceptComment", interceptComment);
    configJO.add("tokenKeywords", tokenKeywordsJA);

    configJO.add("cveAttackModePublicKey", cveAttackModePublicKey);
    configJO.add("cveAttackModePrivateKey", cveAttackModePrivateKey);

    return configJO.toString(WriterConfig.PRETTY_PRINT);
  }
}
