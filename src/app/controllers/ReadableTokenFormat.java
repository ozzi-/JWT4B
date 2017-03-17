package app.controllers;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import app.helpers.CustomJWTToken;

public class ReadableTokenFormat {
	private static final String newline = System.getProperty("line.separator");
	private static final String titleHeaders = "Headers = ";
	private static final String titlePayload = newline + newline + "Payload = ";
	private static final String titleSignature = newline + newline + "Signature = ";
	
	public static String getReadableFormat(CustomJWTToken token) { 

		StringBuilder result = new StringBuilder();

		result.append(titleHeaders);
		result.append(jsonBeautify(token.getHeaderJson()));

		result.append(titlePayload);
		result.append(jsonBeautify(token.getPayloadJson()));

		result.append(titleSignature);
		result.append("\""+token.getSignature()+"\"");
		return result.toString();
	}
	
	public static CustomJWTToken getTokenFromReadableFormat(String token) throws InvalidTokenFormat {
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
		
		return new CustomJWTToken(header, payload, signature);
	}

	private static String jsonBeautify(String input) {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

		JsonNode tree;
		String output;
		try {
			tree = objectMapper.readTree(input);
			output = objectMapper.writeValueAsString(tree);
		} catch (IOException e) {
			return input;
		}
		return output;
	}
	
	private static String jsonMinify(String input) {
		ObjectMapper objectMapper = new ObjectMapper();

		JsonNode tree;
		String output;
		try {
			tree = objectMapper.readTree(input);
			output = objectMapper.writeValueAsString(tree);
		} catch (IOException e) {
			return input;
		}
		return output;
	}

	public static class InvalidTokenFormat extends Exception {
		private static final long serialVersionUID = 1L;
		public InvalidTokenFormat(String message) {
			super(message);
		}
	}
}


