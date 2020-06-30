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
	
	public static PrintWriter stdout;
	public static PrintWriter stderr;

	public static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer", "Authorization: bearer", "authorization: Bearer", "authorization: bearer");
	public static List<String> tokenKeywords = Arrays.asList("id_token", "ID_TOKEN", "access_token", "token");
    public static String highlightColor = "blue";
    public static String interceptComment = "Contains a JWT";
    public static boolean resetEditor = true;
    
	public static String cveAttackModePublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNCJ/1Tawe8DUIbQDxjR"
			+"r+bVSoIdcOjJm5wskbMUjHopTWERzLo65yLPjCVcRudQ8DNJIs3yb+hzxi0b8uyK"
			+"XK6nYTaxdwtRN61NMgI/ecNYw1A3nMLRJ4KetLCUqCehVV+OavJqwGXb0k4OhJu7"
			+"VefLD9PxOQxLd/MxJLMTChqYYQWY069oNTB9uRaBRLwcEv3i8uiM3HAdx4di0FZL"
			+"HN5yAt6Zq7TR53CUDSI74q/AH4zeuo+D/UscVTq2bInfJmN3NdA6XqPdjnu6DtT7"
			+"VQZif+06sFXgnoieuUaeRE0Jn8ZY72hljToFZmsLUPPhTSzmFTgko4+MGnS29w1r"
			+"bQIDAQAB";

	public static String cveAttackModePrivateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC40In/VNrB7wNQ"
			+"htAPGNGv5tVKgh1w6MmbnCyRsxSMeilNYRHMujrnIs+MJVxG51DwM0kizfJv6HPG"
			+"LRvy7IpcrqdhNrF3C1E3rU0yAj95w1jDUDecwtEngp60sJSoJ6FVX45q8mrAZdvS"
			+"Tg6Em7tV58sP0/E5DEt38zEksxMKGphhBZjTr2g1MH25FoFEvBwS/eLy6IzccB3H"
			+"h2LQVksc3nIC3pmrtNHncJQNIjvir8AfjN66j4P9SxxVOrZsid8mY3c10Dpeo92O"
			+"e7oO1PtVBmJ/7TqwVeCeiJ65Rp5ETQmfxljvaGWNOgVmawtQ8+FNLOYVOCSjj4wa"
			+"dLb3DWttAgMBAAECggEBALF/J2ngNxEW2loWf/Bf59NGoQakHF56VFZtEakFEvEv"
			+"ykcUuSGkojmmhyqUHyHBu0xWFSGmJfcwizCD1lnir6f/3aVR//LTHbeZa5Bh9FCf"
			+"Orqqah7WREXr/zyOctdk6F+0HHW+SKRrr0k1yl+1qaABtFaJOR2PH1Qebs5OZjTG"
			+"XvKtm5H7G4FeNPDjprCKB5vRiWPY5F3sRJOFp8TwkH5qbirgZh0KJiYuJMq9Qtzj"
			+"RHYjzALOSWldpqb8Xzcx7lHZbF8gNv3zeRJRJWTYATq8KVaZ3fs0mv9z37MPRC1A"
			+"S9v4ylrwXsAviWvn21Q6E1jrxOxZfAhkoA2aLtFMr4kCgYEA68yc8mupFsRCwcfC"
			+"hauAExibU2lCmW1ImcWxGLQR0dVPyaEPlecwKxvdetWs7BPaxqogKppB71gsxXYA"
			+"SUntgwj1f7zXxo4rdSZv20B09eASo+I8qZpfDZWR1oM7HjXR40lWELtQhzD0QDQC"
			+"UmQtCpVGgyheqPsrQntCeM5LEisCgYEAyKXD93Onevtg6K2GWmnIgCP8+PRvu9kY"
			+"W+3yhN0BGzmJrVSlD6uw0SAsA7awd54Qs00gGcWoztDm7V+YHDcYy3oOzwip4Yw2"
			+"S3kUPewupySLm1VrDBMdXVp1sQH/I5DE3B4c5OxgdCmiX+7hLkXBBjpOqbHS+2bs"
			+"Ps9qnO2M5McCgYAhj84G8yvuAaE+05/sRqzECwyQorrH+7YJrQm36mle5G2m1TXS"
			+"sEU63Yx4n1EtiOXqwOwzJCGeX35/3HvN8qfLrsrCk65ipHmrAv2Ix3PeSzZb/SeF"
			+"PGOrG07WqXcQpbhqEVYeq4qas20QdlaeQ4PlrbmLkYNnqdhObhzX9QTaYQKBgQDD"
			+"a9/fpL8cIrWSKV/Ps3PaijKa7sfcd2coMiqgiPfI4lNbhDN3fcsrA2CbBVX+Su8N"
			+"EzMOptrxA7nGu/JUmL0HgQvnTRLYYE2JWJYEcYJGvGtUkO8/xWY2RCKYkc9Dfn6d"
			+"vJ57wFV5Dgvdz7V18e47+JIg6NcKkIXL7wxxZ1RwhQKBgQDd4nlMdJue4zA7hO2Y"
			+"GxUqX+ALVY6ikZ/SBOQIDrnI9aixwXYQ3t3Nwjim73/0uiLXLOpO92dBSym7GeSP"
			+"YqWZhkyQ8C05tDyGvDI5b7bVmD1pxmnhG9sOktrkDVkOsYUnAhRwCgmuExkoeGWP"
			+"vUt+85cmMpJfHHqbrb5FLqTeXQ==";

    public static String configName = "config.json";
    public static String configFolderName = ".JWT4B";
    public static String configPath = System.getProperty("user.home") + File.separator + configFolderName + File.separator +configName;
	
	public static void loadConfig() {		
		
		File configFile = new File(configPath);
		
        if (!configFile.getParentFile().exists()) {
        	Output.output("Config file directory '"+configFolderName+"' does not exist - creating it");
            configFile.getParentFile().mkdir();
        }
		
		if(!configFile.exists()) {
			Output.output("Config file '"+configPath+"' does not exist - creating it");
			try {
				configFile.createNewFile();
			} catch (IOException e) {
				Output.outputError("Error creating config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
				return;
			}
			String defaultConfigJSONRaw = generateDefaultConfigFile();
			try {
				Files.write(Paths.get(configPath), defaultConfigJSONRaw.getBytes());
			} catch (IOException e) {
				Output.outputError("Error writing config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
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
			
			resetEditor = configJO.getBoolean("resetEditor", true);
			
			highlightColor = configJO.get("highlightColor").asString();
			// 	red, orange, yellow, green, cyan, blue, pink, magenta, gray,or a null String to clear any existing highlight.
			ArrayList<String> allowedColors = new ArrayList<String>(Arrays.asList("red","orange","yellow","green","cyan","blue","pink","magenta","gray"));
			if(!allowedColors.contains(highlightColor)) {
				highlightColor = null;
				Output.output("Unknown color, only 'red, orange, yellow, green, cyan, blue, pink, magenta, gray' is possible - defaulting to null.");
			} 
			
			interceptComment = configJO.get("interceptComment").asString();

			cveAttackModePublicKey = configJO.get("cveAttackModePublicKey").asString();
			cveAttackModePrivateKey = configJO.get("cveAttackModePrivateKey").asString();

		} catch (IOException e) {
			Output.outputError("Error loading config file '"+configPath+"' - message:"+e.getMessage()+" - cause:"+e.getCause().toString());
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
		
		configJO.add("resetEditor", true);
		configJO.add("highlightColor", highlightColor);
		configJO.add("interceptComment", interceptComment);
		configJO.add("jwtKeywords",jwtKeywordsJA);
		configJO.add("tokenKeywords",tokenKeywordsJA);
		
		configJO.add("cveAttackModePublicKey", cveAttackModePublicKey);
		configJO.add("cveAttackModePrivateKey", cveAttackModePrivateKey);
		
		return configJO.toString(WriterConfig.PRETTY_PRINT);
	}
}
