package burp.api.montoya.core;

import burp.api.montoya.http.message.HttpHeader;

public class FakeHttpHeader implements HttpHeader {

	private final String name;
	private final String value;

	public FakeHttpHeader(String name, String value) {
		this.name = name;
		this.value = value;
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
