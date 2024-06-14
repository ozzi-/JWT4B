package burp.api.montoya.core;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

public class FakeParsedHttpParameter extends FakeHttpParameter implements ParsedHttpParameter {

	private final Range nameOffset;
	private final Range valueOffset;

	public FakeParsedHttpParameter(String name, String value, HttpParameterType type, Range nameOffset, Range valueOffset) {
		super(name, value, type);

		this.nameOffset = nameOffset;
		this.valueOffset = valueOffset;
	}

	@Override
	public Range nameOffsets() {
		return nameOffset;
	}

	@Override
	public Range valueOffsets() {
		return valueOffset;
	}
}
