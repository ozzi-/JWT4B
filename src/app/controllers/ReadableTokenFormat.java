package app.controllers;

import model.CustomJWToken;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class ReadableTokenFormat {
	private static final String newline = System.getProperty("line.separator");
	private static final String titleHeaders = "Headers = ";
	private static final String titlePayload = newline + newline + "Payload = ";
	private static final String titleSignature = newline + newline + "Signature = ";
	
	public static String getReadableFormat(CustomJWToken token) { 

		StringBuilder result = new StringBuilder();

		result.append(titleHeaders);
		result.append(jsonBeautify(token.getHeaderJson()));

		result.append(titlePayload);
		result.append(jsonBeautify(token.getPayloadJson()));

		result.append(titleSignature);
		result.append("\""+token.getSignature()+"\"");
		return result.toString();
	}
	
	public static CustomJWToken getTokenFromReadableFormat(String token) throws InvalidTokenFormat {
		if(!token.startsWith(titleHeaders)) { 
			throw new InvalidTokenFormat("Cannot parse token");
		}
	
		token = token.substring(titleHeaders.length());
	
		if(!token.contains(titlePayload)) {
			throw new InvalidTokenFormat("Cannot parse token");
		}
		
		String [] splitted = token.split(titlePayload);
		
		String header = splitted[0];
		String payloadAndSignature = splitted[1];
		
		if(!payloadAndSignature.contains(titleSignature)) {
			throw new InvalidTokenFormat("Cannot parse token");
		}
		
		String [] splitted2 = payloadAndSignature.split(titleSignature);
		
		String payload = splitted2[0];
		String signature = splitted2[1];
		
		return new CustomJWToken(header, payload, signature);
	}
   
	private static String jsonBeautify(String input) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		JsonElement je = JsonParser.parseString(input);
		String prettyJsonString = gson.toJson(je);
		return prettyJsonString;
	}
	
	public static class InvalidTokenFormat extends Exception {
		private static final long serialVersionUID = 1L;
		public InvalidTokenFormat(String message) {
			super(message);
		}
	}
}