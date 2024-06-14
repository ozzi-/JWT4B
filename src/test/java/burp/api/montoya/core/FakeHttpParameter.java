package burp.api.montoya.core;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;

public class FakeHttpParameter implements HttpParameter {

	private final String name;
	private final String value;
	private final HttpParameterType type;

	public FakeHttpParameter(String name, String value, HttpParameterType type) {
		this.name = name;
		this.value = value;
		this.type = type;
	}

	@Override
	public String toString() {
		return "FakeHttpParameter{" + "name='" + name + '\'' + ", value='" + value + '\'' + ", type=" + type + '}';
	}

	public String toNameValueString() {
		return name + "=" + value;
	}

	@Override
	public HttpParameterType type() {
		return type;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public String value() {
		return value;
	}
}