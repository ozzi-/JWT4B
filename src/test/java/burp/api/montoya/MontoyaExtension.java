package burp.api.montoya;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.stubbing.Answer;

import burp.api.montoya.core.FakeHttpHeader;
import burp.api.montoya.core.FakeHttpParameter;
import burp.api.montoya.core.FakeHttpRequest;
import burp.api.montoya.core.FakeHttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;

public class MontoyaExtension implements BeforeAllCallback {
	@Override
	public void beforeAll(ExtensionContext extensionContext) {
		ObjectFactoryLocator.FACTORY = mock(MontoyaObjectFactory.class);

		MontoyaObjectFactory factory = ObjectFactoryLocator.FACTORY;
		when(factory.httpResponse(anyString())).then((Answer<HttpResponse>) i -> new FakeHttpResponse(i.getArgument(0)));
		when(factory.httpRequest(anyString())).then((Answer<HttpRequest>) i -> new FakeHttpRequest(i.getArgument(0)));
		when(factory.httpHeader(anyString(), anyString())).then((Answer<HttpHeader>) i -> new FakeHttpHeader(i.getArgument(0), i.getArgument(1)));
		when(factory.parameter(anyString(), anyString(), any(HttpParameterType.class))).then((Answer<HttpParameter>) i -> new FakeHttpParameter(i.getArgument(0), i.getArgument(1), i.getArgument(2)));
		when(factory.bodyParameter(anyString(), anyString())).then((Answer<HttpParameter>) i -> new FakeHttpParameter(i.getArgument(0), i.getArgument(1), HttpParameterType.BODY));
	}
}