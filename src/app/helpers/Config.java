package app.helpers;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
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

	public static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer", "Authorization: bearer", "authorization: Bearer", "authorization: bearer");
	public static List<String> tokenKeywords = Arrays.asList("id_token", "ID_TOKEN", "access_token", "token");
    public static String highlightColor = "blue";

    public static String configName = "config.json";
    public static String configFolderName = ".JWT4B";
    public static String configPath = System.getProperty("user.home") + File.separator + configFolderName + File.separator +configName;
	
	public static void loadConfig(PrintWriter stdout, PrintWriter stderr) {		
		
		File configFile = new File(configPath);
		
        if (!configFile.getParentFile().exists()) {
    		stdout.println("Config file directory '"+configFolderName+"' does not exist - creating it");
            configFile.getParentFile().mkdir();
        }
		
		if(!configFile.exists()) {
			stdout.println("Config file '"+configPath+"' does not exist - creating it");
			try {
				configFile.createNewFile();
			} catch (IOException e) {
				stderr.println("Error creating config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
				return;
			}
			String defaultConfigJSONRaw = generateDefaultConfigFile();
			try {
				Files.write(Paths.get(configPath), defaultConfigJSONRaw.getBytes());
			} catch (IOException e) {
				stderr.println("Error writing config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
			}
		}
		
		try {
			String configRaw = new String(Files.readAllBytes(Paths.get(configPath)));
			JsonObject configJO = Json.parse(configRaw).asObject();
			
			JsonArray jwtKeywordsJA = configJO.get("jwtKeywords").asArray();
			jwtKeywords = new ArrayList<String>();
			for (JsonValue jwtKeyword : jwtKeywordsJA) {
				jwtKeywords.add(jwtKeyword.asString());
			}
			
			JsonArray tokenKeywordsJA = configJO.get("tokenKeywords").asArray();
			tokenKeywords = new ArrayList<String>();
			for (JsonValue tokenKeyword : tokenKeywordsJA) {
				tokenKeywords.add(tokenKeyword.asString());
			}
			
			highlightColor = configJO.get("highlightColor").asString();
			
			System.out.println(tokenKeywords);
		} catch (IOException e) {
			stderr.println("Error loading config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
		}
	}

	private static String generateDefaultConfigFile() {
		JsonObject configJO = new JsonObject();
		
		JsonArray jwtKeywordsJA = new JsonArray();
		for (String jwtKeyword : jwtKeywords) {
			jwtKeywordsJA.add(jwtKeyword);
		}
		
		JsonArray tokenKeywordsJA = new JsonArray();
		for (String tokenKeyword : tokenKeywords) {
			tokenKeywordsJA.add(tokenKeyword);
		}
		
		configJO.add("highlightColor", highlightColor);
		configJO.add("jwtKeywords",jwtKeywordsJA);
		configJO.add("tokenKeywords",tokenKeywordsJA);
		
		return configJO.toString(WriterConfig.PRETTY_PRINT);
	}
}
