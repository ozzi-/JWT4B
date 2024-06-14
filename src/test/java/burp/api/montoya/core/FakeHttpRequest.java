package burp.api.montoya.core;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class FakeHttpRequest extends FakeHttpMessage implements HttpRequest {

	List<ParsedHttpParameter> parameters = new ArrayList<>();;

	private FakeHttpRequest(FakeHttpRequest request, HttpParameter parameter) {
		this(request.rawContent);

		// update parameters
		parameters = parameters.stream()
				.map(o -> o.name().equals(parameter.name()) ? new FakeParsedHttpParameter(parameter.name(), parameter.value(), parameter.type(), new FakeRange(0, 0), new FakeRange(0, 0)) : o)
				.toList();

		// update body
		this.body = parameters.stream().filter(o -> o.type() == HttpParameterType.BODY).map(o -> ((FakeParsedHttpParameter) o).toNameValueString()).collect(Collectors.joining("&"));

		// update raw content
		this.rawContent = this.header + "\r\n" + this.body;
	}

	public FakeHttpRequest(String request) {
		super(request);

		processBody();
	}

	private void processBody() {
		List<String> params = List.of(body.split("&"));
		for (String param : params) {
			String[] keyValue = param.split("=");
			if (keyValue.length == 2) {
				String name = keyValue[0].trim();
				String value = keyValue[1].trim();

				// range is not yet supported
				parameters.add(new FakeParsedHttpParameter(name, value, HttpParameterType.BODY, new FakeRange(0, 0), new FakeRange(0, 1)));
			}
		}
	}

	@Override
	public boolean isInScope() {
		System.err.println("Not implemented");
		return false;
	}

	@Override
	public HttpService httpService() {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public String url() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public String method() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public String path() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public String query() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public String pathWithoutQuery() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public String fileExtension() {
		System.err.println("Not implemented");
		return "";
	}

	@Override
	public ContentType contentType() {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public List<ParsedHttpParameter> parameters() {
		return parameters;
	}

	@Override
	public List<ParsedHttpParameter> parameters(HttpParameterType type) {
		return parameters.stream().filter(parameter -> (parameter.type() == type)).toList();
	}

	@Override
	public boolean hasParameters() {
		return !parameters.isEmpty();
	}

	@Override
	public boolean hasParameters(HttpParameterType type) {
		return !parameters.stream().filter(parameter -> (parameter.type() == type)).toList().isEmpty();
	}

	@Override
	public ParsedHttpParameter parameter(String name, HttpParameterType type) {
		return parameters.stream().filter(parameter -> (parameter.name().equals(name) && (parameter.type() == type))).findAny().orElse(null);
	}

	@Override
	public String parameterValue(String name, HttpParameterType type) {
		return parameters.stream().filter(parameter -> (parameter.name().equals(name) && (parameter.type() == type))).findAny().map(ParsedHttpParameter::value).orElse(null);
	}

	@Override
	public boolean hasParameter(String name, HttpParameterType type) {
		return parameters.stream().anyMatch(parameter -> (parameter.name().equals(name) && parameter.type() == type));
	}

	@Override
	public boolean hasParameter(HttpParameter parameter) {
		System.err.println("Not implemented");
		return false;
	}

	@Override
	public HttpRequest copyToTempFile() {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withService(HttpService service) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withPath(String path) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withMethod(String method) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withHeader(HttpHeader header) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withHeader(String name, String value) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withParameter(HttpParameter parameter) {
		return new FakeHttpRequest(this, parameter);
	}

	@Override
	public HttpRequest withAddedParameters(List<? extends HttpParameter> parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withAddedParameters(HttpParameter... parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withRemovedParameters(List<? extends HttpParameter> parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withRemovedParameters(HttpParameter... parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withUpdatedParameters(List<? extends HttpParameter> parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withUpdatedParameters(HttpParameter... parameters) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withTransformationApplied(HttpTransformation transformation) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withBody(String body) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withBody(ByteArray body) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withAddedHeader(String name, String value) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withAddedHeader(HttpHeader header) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withUpdatedHeader(String name, String value) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withUpdatedHeader(HttpHeader header) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withRemovedHeader(String name) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withRemovedHeader(HttpHeader header) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withMarkers(List<Marker> markers) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withMarkers(Marker... markers) {
		System.err.println("Not implemented");
		return null;
	}

	@Override
	public HttpRequest withDefaultHeaders() {
		System.err.println("Not implemented");
		return null;
	}
}
