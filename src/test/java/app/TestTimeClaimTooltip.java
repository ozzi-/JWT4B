package app;

import java.util.TimeZone;

import org.junit.jupiter.api.Test;

import app.helpers.TimeClaimTooltip;
import app.helpers.TimeClaimTooltip.ClaimMatch;

import static org.assertj.core.api.Assertions.assertThat;

class TestTimeClaimTooltip {

	private static final TimeZone VN = TimeZone.getTimeZone("Asia/Ho_Chi_Minh"); // UTC+7, no DST

	// ---- match() ----

	@Test
	void matchesExpLineAndLocatesValueSpan() {
		String line = "  \"exp\": 1700000000,";
		ClaimMatch m = TimeClaimTooltip.match(line);
		assertThat(m).isNotNull();
		assertThat(m.claim).isEqualTo("exp");
		assertThat(m.epochSeconds).isEqualTo(1700000000L);
		assertThat(line.substring(m.valueStart, m.valueEnd)).isEqualTo("1700000000");
	}

	@Test
	void matchesWithoutWhitespaceAroundColon() {
		ClaimMatch m = TimeClaimTooltip.match("\"exp\":1700000000");
		assertThat(m).isNotNull();
		assertThat(m.epochSeconds).isEqualTo(1700000000L);
	}

	@Test
	void returnsNullForNonTimeClaimLine() {
		assertThat(TimeClaimTooltip.match("  \"sub\": \"admin\",")).isNull();
	}

	// ---- format(): exp ----

	@Test
	void formatsValidExpWithBothTimezonesRelativeAndStatus() {
		String html = TimeClaimTooltip.format("exp", 1700000000L, 1699996400L, VN); // expires in 1h
		assertThat(html).contains("exp");
		assertThat(html).contains("Expiration");
		assertThat(html).contains("UTC: 2023-11-14 22:13:20");
		assertThat(html).contains("Local: 2023-11-15 05:13:20");
		assertThat(html).contains("VALID");
		assertThat(html).contains("in 1 hour");
	}

	@Test
	void formatsExpiredExp() {
		String html = TimeClaimTooltip.format("exp", 1700000000L, 1700003600L, VN); // expired 1h ago
		assertThat(html).contains("EXPIRED");
		assertThat(html).contains("1 hour ago");
	}

	@Test
	void warnsWhenExpiringSoon() {
		String html = TimeClaimTooltip.format("exp", 1700000060L, 1700000000L, VN); // expires in 60s
		assertThat(html).contains("EXPIRING SOON");
		assertThat(html).contains("in 1 minute");
		assertThat(html).doesNotContain("EXPIRED");
	}

	@Test
	void humanizesPluralUnits() {
		String html = TimeClaimTooltip.format("exp", 1700007200L, 1700000000L, VN); // expires in 2h
		assertThat(html).contains("in 2 hours");
	}

	// ---- format(): nbf ----

	@Test
	void formatsNbfNotYetValid() {
		String html = TimeClaimTooltip.format("nbf", 1700000000L, 1699996400L, VN); // active in 1h
		assertThat(html).contains("nbf");
		assertThat(html).contains("NOT YET VALID");
	}

	// ---- format(): iat ----

	@Test
	void formatsIatWithoutPassFailStatus() {
		String html = TimeClaimTooltip.format("iat", 1700000000L, 1700003600L, VN); // issued 1h ago
		assertThat(html).contains("iat");
		assertThat(html).contains("1 hour ago");
		assertThat(html).doesNotContain("EXPIRED");
		assertThat(html).doesNotContain("VALID");
	}

	// ---- configured local zone (captured before JWT4B forces the JVM default to UTC) ----

	@Test
	void twoArgFormatUsesConfiguredLocalZone() {
		TimeZone previous = TimeZone.getTimeZone("UTC");
		try {
			TimeClaimTooltip.setLocalZone(VN);
			ClaimMatch m = TimeClaimTooltip.match("\"exp\": 1700000000");
			String html = TimeClaimTooltip.format(m, 1699996400L);
			assertThat(html).contains("UTC: 2023-11-14 22:13:20");
			assertThat(html).contains("Local: 2023-11-15 05:13:20");
		} finally {
			TimeClaimTooltip.setLocalZone(previous);
		}
	}

	// ---- OS time-zone detection (independent of the clobbered JVM default) ----

	@Test
	void resolvesZoneFromEtcTimezone() {
		TimeZone z = TimeClaimTooltip.resolveOsZone(null, "Asia/Ho_Chi_Minh", null);
		assertThat(z).isNotNull();
		assertThat(z.getID()).isEqualTo("Asia/Ho_Chi_Minh");
	}

	@Test
	void resolvesZoneFromLocaltimeSymlinkPath() {
		TimeZone z = TimeClaimTooltip.resolveOsZone(null, null, "/usr/share/zoneinfo/Asia/Ho_Chi_Minh");
		assertThat(z).isNotNull();
		assertThat(z.getID()).isEqualTo("Asia/Ho_Chi_Minh");
	}

	@Test
	void tzEnvTakesPrecedenceOverFiles() {
		TimeZone z = TimeClaimTooltip.resolveOsZone("Europe/Paris", "Asia/Ho_Chi_Minh", null);
		assertThat(z.getID()).isEqualTo("Europe/Paris");
	}

	@Test
	void returnsNullWhenNoOsZoneInfoAvailable() {
		assertThat(TimeClaimTooltip.resolveOsZone(null, null, null)).isNull();
	}

	@Test
	void returnsNullForUnknownZoneId() {
		assertThat(TimeClaimTooltip.resolveOsZone(null, "Not/AZone", null)).isNull();
	}
}
