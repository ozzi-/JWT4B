package app.controllers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ReadableTokenFormatTest {

    static Stream<Arguments> data() {
        return Stream.of(
                arguments(null, ""),
                arguments("", ""),
                arguments(" ", ""),
                arguments("\t", ""),
                arguments("{\"alg\":\"HS256\",\"typ\":", "{\"alg\":\"HS256\",\"typ\":"),
                arguments("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}"),
                arguments("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}", "{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\",\n  \"admin\": true\n}"),
                arguments("{\n   \"sub\":\"1234567890\",\n   \"name\":\"John Doe\",\n   \"admin\":true\n}", "{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\",\n  \"admin\": true\n}"),
                arguments("{\"sub\":\"1234567890\",\"name\":\"Max Musterli\",\"admin\":true}", "{\n  \"sub\": \"1234567890\",\n  \"name\": \"Max Musterli\",\n  \"admin\": true\n}"),
                arguments("{\"alg\":\"HS256\",\"kid\":\"Z4osLouitTFO+A+xOZ/YcdtlW04=\"}", "{\n  \"alg\": \"HS256\",\n  \"kid\": \"Z4osLouitTFO+A+xOZ/YcdtlW04=\"\n}")
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void testJsonBeautify(String json, String expectedBeautifulJson) {
        String beautifulJson = ReadableTokenFormat.jsonBeautify(json);

        assertThat(beautifulJson).isEqualTo(expectedBeautifulJson);
    }
}