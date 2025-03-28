package app.helpers;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import app.algorithm.AlgorithmWrapper;
import app.tokenposition.ITokenPosition;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import lombok.Getter;
import model.CustomJWToken;

public class SecretFinder {
	private static final String RE_TOP = "[\\w-]+\\.(com.cn|net.cn|gov.cn|org\\.nz|org.cn|com|net|org|gov|cc|biz|info|cn|co)\\b";
	private static final Pattern DOMAIN_PATTERN = Pattern.compile(RE_TOP, Pattern.CASE_INSENSITIVE);

	private final String jwt;
	private final String jwtPayload;
	private final String algorithm;

	@Getter
	private final List<String> secrets;
	private final HttpRequestToBeSent httpRequestToBeSent;

	public SecretFinder(ITokenPosition tokenPosition, HttpRequestToBeSent requestToBeSent) {
		CustomJWToken cjwt = new CustomJWToken(Objects.requireNonNull(tokenPosition).getToken());
		this.jwt = Objects.requireNonNull(tokenPosition).getToken();
		this.jwtPayload = cjwt.getPayloadJson();
		this.algorithm = cjwt.getAlgorithm();
		this.httpRequestToBeSent = requestToBeSent;
		this.secrets = collectSecrets();

	}

	public List<String> collectSecrets() {
		Set<String> secretSet = new LinkedHashSet<>();

		String host = getHost();
		secretSet.add(host);

		String domainName = getDomainName(host);
		secretSet.add(domainName);

		String domain = getDomain(host);
		secretSet.add(domain);

		List<String> values = getAllValues(this.jwtPayload);
		secretSet.addAll(values);

		ArrayList<String> upperSecrets = secretSet.stream().map(String::toUpperCase).collect(Collectors.toCollection(ArrayList::new));
		secretSet.addAll(upperSecrets);

		return new ArrayList<>(secretSet);

	}

	public String getDomainName(String host) {
		try {
			Matcher matcher = DOMAIN_PATTERN.matcher(host);
			if (matcher.find()) {
				return matcher.group();
			}
		} catch (IllegalStateException | IndexOutOfBoundsException e) {
			Output.outputError("Failed to extract domain: " + e.getMessage());
		}
		return "";
	}

	public String getDomain(String host) {
		return Optional.ofNullable(getDomainName(host)).map(domainName -> domainName.split("\\.")[0]).orElse("");
	}

	public String getHost() {
		String urlString = this.httpRequestToBeSent.url();
		String host = "";
		try {
			URI uri = new URI(urlString);
			URL url = uri.toURL();
			host = url.getHost();
		} catch (Exception e) {
			Output.outputError("URL Parse Error: " + e.getMessage());
		}

		return host;
	}

	public static List<String> getAllValues(String jsonString) {
		ArrayList<String> values = new ArrayList<>();
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			JsonNode rootNode = objectMapper.readTree(jsonString);
			extractValues(rootNode, values);
		} catch (Exception e) {
			Output.outputError(e.getMessage());
		}
		return values;
	}

	private static void extractValues(JsonNode node, ArrayList<String> values) {
		if (node.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
			while (fields.hasNext()) {
				extractValues(fields.next().getValue(), values);
			}
		} else if (node.isArray()) {
			for (JsonNode arrayElement : node) {
				extractValues(arrayElement, values);
			}
		} else {
			values.add(node.asText());
		}
	}

	public Boolean checkSecret(String secret) {
		try {
			JWTVerifier verifier = JWT.require(AlgorithmWrapper.getVerifierAlgorithm(this.algorithm, secret)).build();
			verifier.verify(this.jwt);
			return true;
		} catch (Exception ignored) {
			return false;
		}
	}
}
