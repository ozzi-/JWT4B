package burp.api.montoya.core;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;

import java.util.List;

public class FakeHttpResponse extends FakeHttpMessage implements HttpResponse {

	public FakeHttpResponse(String message) {
		super(message);
	}

	@Override
	public short statusCode() {
		return 0;
	}

	@Override
	public String reasonPhrase() {
		return "";
	}

	@Override
	public boolean isStatusCodeClass(StatusCodeClass statusCodeClass) {
		return false;
	}

	@Override
	public List<Cookie> cookies() {
		return List.of();
	}

	@Override
	public Cookie cookie(String name) {
		return null;
	}

	@Override
	public String cookieValue(String name) {
		return "";
	}

	@Override
	public boolean hasCookie(String name) {
		return false;
	}

	@Override
	public boolean hasCookie(Cookie cookie) {
		return false;
	}

	@Override
	public MimeType mimeType() {
		return null;
	}

	@Override
	public MimeType statedMimeType() {
		return null;
	}

	@Override
	public MimeType inferredMimeType() {
		return null;
	}

	@Override
	public List<KeywordCount> keywordCounts(String... keywords) {
		return List.of();
	}

	@Override
	public List<Attribute> attributes(AttributeType... types) {
		return List.of();
	}

	@Override
	public HttpResponse copyToTempFile() {
		return null;
	}

	@Override
	public HttpResponse withStatusCode(short statusCode) {
		return null;
	}

	@Override
	public HttpResponse withReasonPhrase(String reasonPhrase) {
		return null;
	}

	@Override
	public HttpResponse withHttpVersion(String httpVersion) {
		return null;
	}

	@Override
	public HttpResponse withBody(String body) {
		return null;
	}

	@Override
	public HttpResponse withBody(ByteArray body) {
		return null;
	}

	@Override
	public HttpResponse withAddedHeader(HttpHeader header) {
		return null;
	}

	@Override
	public HttpResponse withAddedHeader(String name, String value) {
		return null;
	}

	@Override
	public HttpResponse withUpdatedHeader(HttpHeader header) {
		return null;
	}

	@Override
	public HttpResponse withUpdatedHeader(String name, String value) {
		return null;
	}

	@Override
	public HttpResponse withRemovedHeader(HttpHeader header) {
		return null;
	}

	@Override
	public HttpResponse withRemovedHeader(String name) {
		return null;
	}

	@Override
	public HttpResponse withMarkers(List<Marker> markers) {
		return null;
	}

	@Override
	public HttpResponse withMarkers(Marker... markers) {
		return null;
	}
}
