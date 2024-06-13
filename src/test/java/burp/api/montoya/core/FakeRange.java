// copied from https://github.com/Hannah-PortSwigger/WebSocketTurboIntruder/blob/main/src/test/java/burp/api/montoya/core/FakeRange.java

package burp.api.montoya.core;

import java.util.Objects;

public class FakeRange implements Range {
	private final int start;
	private final int end;

	public FakeRange(int start, int end) {
		this.start = start;
		this.end = end;
	}

	@Override
	public int startIndexInclusive() {
		return start;
	}

	@Override
	public int endIndexExclusive() {
		return end;
	}

	@Override
	public boolean contains(int i) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}

		return o instanceof Range range && startIndexInclusive() == range.startIndexInclusive() && endIndexExclusive() == range.endIndexExclusive();
	}

	@Override
	public int hashCode() {
		return Objects.hash(start, end);
	}

	@Override
	public String toString() {
		return "Range{" + "start=" + start + ", end=" + end + '}';
	}

	public static Range rangeOf(int start, int end) {
		return new FakeRange(start, end);
	}
}