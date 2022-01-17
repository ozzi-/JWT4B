package app;

import app.helpers.KeyValuePair;
import app.tokenposition.Body;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static app.TestTokens.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TestBodyDetection {

    static Stream<Arguments> bodyDataAndDetectedTokens() {
        return Stream.of(
                arguments("test=best&abc=" + HS256_TOKEN, HS256_TOKEN),
                arguments("a " + HS256_TOKEN + " b", HS256_TOKEN),
                arguments("{\"aaaa\":\"" + HS256_TOKEN + "\"}", HS256_TOKEN),
                arguments("{ \"bbbb\" : { \" cccc \": { \" dddd\":\"" + HS256_TOKEN + " \"}}}", HS256_TOKEN),
                arguments("token=" + HS256_TOKEN, HS256_TOKEN),
                arguments(HS256_TOKEN, HS256_TOKEN),
                arguments("egg=" + HS256_TOKEN + "&test=best", HS256_TOKEN)
        );
    }

    @MethodSource("bodyDataAndDetectedTokens")
    @ParameterizedTest
    void testBodyDetection(String body, String bodyToken) {
        Body pb = new Body(null, body);

        KeyValuePair result = pb.getJWTFromBody();

        assertThat(result.getValue()).isEqualTo(bodyToken);
    }

    static Stream<Arguments> bodyDataWhereNoTokenDetected() {
        return Stream.of(
                arguments("{ \"bbbb\" : { \" cccc \": { \" dddd\":" + HS256_TOKEN + " \"}}}"),
                arguments("{}"),
                arguments("yo=" + INVALID_TOKEN + "&test=best"),
                arguments("ab " + INVALID_TOKEN + " de"),
                arguments(HS256_TOKEN + "&"),
                arguments("")
        );
    }

    @MethodSource("bodyDataWhereNoTokenDetected")
    @ParameterizedTest
    void testBodyDetection(String body) {
        Body pb = new Body(null, body);

        KeyValuePair result = pb.getJWTFromBody();

        assertThat(result).isNull();
    }

    @Test
    void testPostBodyReplaceWithParam() {
        String body = "test=best&token=" + HS256_TOKEN;
        Body pb = new Body(null, body);
        @SuppressWarnings("unused")
        KeyValuePair result = pb.getJWTFromBody();
        pb.getToken();
        String replaced = pb.replaceTokenImpl(HS256_TOKEN_2, body);
        Body pbR = new Body(null, replaced);
        KeyValuePair resultR = pbR.getJWTFromBody();
        assertThat(resultR.getValue()).isEqualTo(HS256_TOKEN_2);
    }

    @Test
    void testPostBodyReplaceWithoutParam() {
        String body = "ab\n cd " + HS256_TOKEN + " cd";
        Body pb = new Body(null, body);
        @SuppressWarnings("unused")
        KeyValuePair result = pb.getJWTFromBody();
        pb.getToken();
        String replaced = pb.replaceTokenImpl(HS256_TOKEN_2, body);
        Body pbR = new Body(null, replaced);
        KeyValuePair resultR = pbR.getJWTFromBody();
        assertThat(resultR.getValue()).isEqualTo(HS256_TOKEN_2);
    }
}
