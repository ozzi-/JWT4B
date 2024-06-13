package burp.api.montoya.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;

public class FakeHttpMessage implements HttpMessage {

    String rawContent;

    String header;
    String body;

    List<HttpHeader> headerList = new ArrayList<>();

    public FakeHttpMessage(String message) {
        super();
        rawContent = message;

        splitHeaderAndBody();
        processHeader();
    }

    private void processHeader() {
        List<String> lines = List.of(header.split("\r\n"));
        for (String line : lines) {
            // body reached
            if (line.isBlank()) {
                return;
            }

            int colon = line.indexOf(':');

            if (colon > -1) {
                headerList.add(HttpHeader.httpHeader(line.substring(0, colon), line.substring(colon + 1).trim()));
            }
        }
    }

    public String toString() {
        return rawContent;
    }

    private void splitHeaderAndBody() {
        Scanner scanner = new Scanner(this.rawContent);
        String delimiter = "\r\n";
        scanner.useDelimiter(delimiter);
        StringBuilder sb=new StringBuilder();
        List<String> result=new ArrayList<>();
        while (scanner.hasNextLine()){
            String line = scanner.nextLine();
            if(!(line.trim().isEmpty())){
                sb.append(line).append(delimiter);
            }else if(!sb.toString().isEmpty()) {
                result.add(sb.toString());
                sb.setLength(0);
            }
        }
        if(!sb.toString().isEmpty()) {
            result.add(sb.toString());
        }

        header = result.get(0);

        if (result.size() > 1) {
            body = result.get(1).trim(); // TODO
        } else {
            body = "";
        }
    }

    @Override
    public boolean hasHeader(HttpHeader header) {
        return headerList.stream()
                .anyMatch(o -> o.equals(header));
    }

    @Override
    public boolean hasHeader(String name) {
        return headerList.stream()
                .anyMatch(o -> o.name().equals(name));
    }

    @Override
    public boolean hasHeader(String name, String value) {
        return headerList.stream()
                .anyMatch(o -> o.name().equals(name) && o.value().equals(value));
    }

    @Override
    public HttpHeader header(String name) {
        return headerList.stream()
                .filter(o -> o.name().equals(name))
                .findFirst()
                .orElse(null);
    }

    @Override
    public String headerValue(String name) {
        return headerList.stream()
                .filter(o -> o.name().equals(name))
                .map(HttpHeader::value)
                .findFirst()
                .orElse(null);
    }

    @Override
    public List<HttpHeader> headers() {
        return headerList;
    }

    @Override
    public String httpVersion() {
        System.err.println("Not implemented");
        return "";
    }

    @Override
    public int bodyOffset() {
        System.err.println("Not implemented");
        return 0;
    }

    @Override
    public ByteArray body() {
        System.err.println("Not implemented");
        return null;
    }

    @Override
    public String bodyToString() {
        return body;
    }

    @Override
    public List<Marker> markers() {
        System.err.println("Not implemented");
        return List.of();
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        System.err.println("Not implemented");
        return false;
    }

    @Override
    public boolean contains(Pattern pattern) {
        System.err.println("Not implemented");
        return false;
    }

    @Override
    public ByteArray toByteArray() {
        System.err.println("Not implemented");
        return null;
    }
}
