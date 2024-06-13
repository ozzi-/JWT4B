package app;

import app.tokenposition.Body;
import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static app.TestConstants.*;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ExtendWith(MontoyaExtension.class)
class TestBodyDetection {

    static Stream<Arguments> bodyDataAndDetectedTokens() {
        return Stream.of(
                arguments("test=best&abc=" + HS256_TOKEN, HS256_TOKEN),
                arguments("a " + HS256_TOKEN + " b", HS256_TOKEN),
                arguments("{\"aaaa\":\"" + HS256_TOKEN + "\"}", HS256_TOKEN),
                arguments("{ \"bbbb\" : { \" cccc \": { \" dddd\":\"" + HS256_TOKEN + " \"}}}", HS256_TOKEN),
                arguments("token=" + HS256_TOKEN, HS256_TOKEN),
                arguments(HS256_TOKEN, HS256_TOKEN),
                arguments("egg=" + HS256_TOKEN + "&test=best", HS256_TOKEN),
                arguments("abc def " + HS256_TOKEN + " ghi jkl", HS256_TOKEN)
        );
    }

    @MethodSource("bodyDataAndDetectedTokens")
    @ParameterizedTest
    void testBodyDetection(String body, String bodyToken) {
        Map<String, Object> params = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body);

        HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));

        Body pb = new Body(httpRequest, true);

        assertThat(pb.positionFound()).isTrue();
        assertThat(pb.getToken()).isEqualTo(bodyToken);
    }

    static Stream<Arguments> bodyDataWhereNoTokenDetected() {
        return Stream.of(
                arguments("{ \"bbbb\" : { \" cccc \": { \" dddd\":" + HS256_TOKEN + " \"}}}"),
                arguments("{}"),
                arguments("{ \"abc\": \"def\"}"),
                arguments("{ \"abc\": {\"def\" : \"ghi\"} }"),
                arguments("yo=" + INVALID_HEADER_TOKEN + "&test=best"),
                arguments("ab " + INVALID_HEADER_TOKEN + " de"),
                arguments(HS256_TOKEN + "&"),
                arguments("abc def ghi jkl"),
                arguments("")
        );
    }

    @MethodSource("bodyDataWhereNoTokenDetected")
    @ParameterizedTest
    void testBodyDetection(String body) {
        Map<String, Object> params = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body);

        HttpRequest httpRequest = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params));

        Body pb = new Body(httpRequest, true);

        assertThat(pb.positionFound()).isFalse();
    }


    @Test
    void testPostBodyReplaceWithParam() {
        String body1 = "test=best&token=" + HS256_TOKEN;

        Map<String, Object> params1 = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body1);

        HttpRequest httpRequest1 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params1));

        Body pb1 = new Body(httpRequest1, true);
        pb1.positionFound();
        pb1.replaceToken(HS256_TOKEN_2);

        //
        String body2 = "test=best&token=" + HS256_TOKEN_2;

        Map<String, Object> params2 = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body2);

        HttpRequest httpRequest2 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params2));

        Body pb2 = new Body(httpRequest2, true);
        pb2.positionFound();

        //
        assertThat(pb1.getRequest().toString()).isEqualTo(pb2.getRequest().toString());
    }


    @Test
    void testPostBodyReplaceWithoutParam() {
        String body1 = "ab\n cd " + HS256_TOKEN + " cd";

        Map<String, Object> params1 = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body1);

        HttpRequest httpRequest1 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params1));

        Body pb1 = new Body(httpRequest1, true);
        pb1.positionFound();
        pb1.replaceToken(HS256_TOKEN_2);

        //
        String body2 = "ab\n cd " + HS256_TOKEN_2 + " cd";

        Map<String, Object> params2 = Map.of(
                "METHOD", METHOD_POST,
                "BODY", body2);

        HttpRequest httpRequest2 = httpRequest(StringSubstitutor.replace(REQUEST_TEMPLATE, params2));

        Body pb2 = new Body(httpRequest2, true);
        pb2.positionFound();

        //
        assertThat(pb1.getRequest().toString()).isEqualTo(pb2.getRequest().toString());
    }
}
