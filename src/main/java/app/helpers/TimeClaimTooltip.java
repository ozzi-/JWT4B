package app.helpers;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds a human-readable hover tooltip for the JWT time claims (exp / nbf / iat).
 *
 * <p>Pure, side-effect-free logic so it can be unit-tested without a GUI. The Swing layer
 * ({@code RSyntaxTextAreaFactory}) locates the claim value under the mouse via {@link #match(String)}
 * and renders {@link #format(ClaimMatch, long)}.
 *
 * <p>Epoch values are interpreted as <b>seconds</b> (JWT NumericDate), matching the rest of JWT4B.
 */
public final class TimeClaimTooltip {

	private TimeClaimTooltip() {
	}

	/** Matches a registered time claim and captures its numeric value: {@code "exp": 1700000000}. */
	private static final Pattern CLAIM = Pattern.compile("\"(exp|nbf|iat)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)");

	private static final long YEAR = 31536000L; // 365 days
	private static final long DAY = 86400L;
	private static final long HOUR = 3600L;
	private static final long MINUTE = 60L;

	/** An exp this close to now (or closer) is flagged as expiring soon. */
	private static final long WARN_SECONDS = 300L; // 5 minutes

	/**
	 * The real OS time zone. JWT4B calls {@code TimeZone.setDefault(UTC)} globally while parsing
	 * claims, and that clobber survives extension reloads within a Burp session, so
	 * {@code TimeZone.getDefault()} can no longer be trusted for the local time. We read the OS zone
	 * directly (TZ env, /etc/timezone, /etc/localtime) and only fall back to the JVM default.
	 */
	private static volatile TimeZone localZone = detectOsZone();

	/** Overrides the local time zone (used by tests). */
	public static void setLocalZone(TimeZone tz) {
		if (tz != null) {
			localZone = tz;
		}
	}

	private static TimeZone detectOsZone() {
		TimeZone z = resolveOsZone(System.getenv("TZ"), readFirstLine("/etc/timezone"), readSymlinkTarget("/etc/localtime"));
		return z != null ? z : TimeZone.getDefault();
	}

	/**
	 * Resolves an OS time zone from the three common Unix sources, in priority order:
	 * the {@code TZ} env var, the contents of {@code /etc/timezone}, then the target of the
	 * {@code /etc/localtime} symlink. Pure (no I/O) so it can be unit-tested.
	 *
	 * @return the zone, or {@code null} if none of the inputs names a known zone.
	 */
	public static TimeZone resolveOsZone(String tzEnv, String etcTimezone, String localtimeLinkTarget) {
		String id = firstNonBlank(tzEnv, etcTimezone, zoneIdFromPath(localtimeLinkTarget));
		if (id == null) {
			return null;
		}
		TimeZone z = TimeZone.getTimeZone(id);
		// TimeZone.getTimeZone() returns GMT for unknown ids, so only trust an exact round-trip.
		return z.getID().equals(id) ? z : null;
	}

	static String zoneIdFromPath(String path) {
		if (path == null) {
			return null;
		}
		int i = path.indexOf("zoneinfo/");
		if (i < 0) {
			return null;
		}
		String id = path.substring(i + "zoneinfo/".length()).trim();
		return id.isEmpty() ? null : id;
	}

	private static String firstNonBlank(String... values) {
		for (String v : values) {
			if (v != null && !v.trim().isEmpty()) {
				return v.trim();
			}
		}
		return null;
	}

	private static String readFirstLine(String path) {
		try {
			Path p = Paths.get(path);
			if (Files.isReadable(p)) {
				for (String line : Files.readAllLines(p)) {
					if (!line.trim().isEmpty()) {
						return line.trim();
					}
				}
			}
		} catch (Exception ignored) {
			// not available on this OS
		}
		return null;
	}

	private static String readSymlinkTarget(String path) {
		try {
			Path p = Paths.get(path);
			if (Files.exists(p)) {
				return p.toRealPath().toString();
			}
		} catch (Exception ignored) {
			// not available on this OS
		}
		return null;
	}

	/** A time claim found on a line of text, with the character span of its value. */
	public static final class ClaimMatch {
		public final String claim;
		public final long epochSeconds;
		public final int valueStart; // inclusive, index within the matched line
		public final int valueEnd;   // exclusive

		ClaimMatch(String claim, long epochSeconds, int valueStart, int valueEnd) {
			this.claim = claim;
			this.epochSeconds = epochSeconds;
			this.valueStart = valueStart;
			this.valueEnd = valueEnd;
		}
	}

	/**
	 * Finds the first exp/nbf/iat numeric claim on {@code line}.
	 *
	 * @return the match, or {@code null} if the line holds no such claim.
	 */
	public static ClaimMatch match(String line) {
		if (line == null) {
			return null;
		}
		Matcher m = CLAIM.matcher(line);
		if (!m.find()) {
			return null;
		}
		long epoch;
		try {
			epoch = (long) Double.parseDouble(m.group(2));
		} catch (NumberFormatException e) {
			return null;
		}
		return new ClaimMatch(m.group(1), epoch, m.start(2), m.end(2));
	}

	/** Formats a matched claim using the captured local time zone for the local line. */
	public static String format(ClaimMatch m, long nowSeconds) {
		return format(m.claim, m.epochSeconds, nowSeconds, localZone);
	}

	/** Formats a time claim as an HTML tooltip. {@code localZone} is injectable for deterministic tests. */
	public static String format(String claim, long epochSeconds, long nowSeconds, TimeZone localZone) {
		String label;
		switch (claim) {
			case "exp":
				label = "Expiration time";
				break;
			case "nbf":
				label = "Not valid before";
				break;
			case "iat":
				label = "Issued at";
				break;
			default:
				label = claim;
				break;
		}

		String utc = formatAbsolute(epochSeconds, TimeZone.getTimeZone("UTC"));
		String local = formatAbsolute(epochSeconds, localZone);
		long diff = epochSeconds - nowSeconds; // > 0 => in the future

		StringBuilder sb = new StringBuilder();
		sb.append("<html>");
		sb.append("<b>").append(claim).append("</b> — ").append(label).append("<br>");
		sb.append("<b>UTC: ").append(utc).append("</b><br>");
		sb.append("<b>Local: ").append(local).append("</b> (").append(tzLabel(localZone, epochSeconds)).append(")<br>");
		sb.append(statusLine(claim, diff));
		sb.append("</html>");
		return sb.toString();
	}

	private static String statusLine(String claim, long diff) {
		switch (claim) {
			case "exp":
				if (diff <= 0) {
					return status("EXPIRED", "red") + " — " + humanize(diff) + " ago";
				}
				if (diff <= WARN_SECONDS) {
					return status("⚠ EXPIRING SOON", "orange") + " — in " + humanize(diff);
				}
				return status("VALID", "green") + " — in " + humanize(diff);
			case "nbf":
				return diff > 0
						? status("NOT YET VALID", "red") + " — active in " + humanize(diff)
						: status("ACTIVE", "green") + " — valid since " + humanize(diff) + " ago";
			case "iat":
				return diff > 0
						? "<b>Issued:</b> in " + humanize(diff)
						: "<b>Issued:</b> " + humanize(diff) + " ago";
			default:
				return "";
		}
	}

	private static String status(String text, String color) {
		return "<b>Status:</b> <span style=\"color:" + color + "\">" + text + "</span>";
	}

	private static String formatAbsolute(long epochSeconds, TimeZone tz) {
		SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		f.setTimeZone(tz);
		return f.format(new Date(epochSeconds * 1000L));
	}

	private static String tzLabel(TimeZone tz, long epochSeconds) {
		SimpleDateFormat f = new SimpleDateFormat("XXX"); // ISO-8601 offset, e.g. +07:00
		f.setTimeZone(tz);
		return "GMT" + f.format(new Date(epochSeconds * 1000L));
	}

	/** Renders a duration in English (pluralized), keeping the two largest non-zero units. */
	private static String humanize(long seconds) {
		long s = Math.abs(seconds);
		if (s == 0) {
			return "now";
		}
		long[] sizes = { YEAR, DAY, HOUR, MINUTE, 1L };
		String[] names = { "year", "day", "hour", "minute", "second" };
		StringBuilder sb = new StringBuilder();
		int used = 0;
		for (int i = 0; i < sizes.length && used < 2; i++) {
			long q = s / sizes[i];
			if (q > 0) {
				if (used > 0) {
					sb.append(" ");
				}
				sb.append(q).append(" ").append(names[i]);
				if (q != 1) {
					sb.append("s");
				}
				s -= q * sizes[i];
				used++;
			}
		}
		return sb.toString();
	}
}
