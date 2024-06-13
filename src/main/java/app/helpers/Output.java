package app.helpers;

import burp.api.montoya.logging.Logging;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class Output {
	private static final DateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

	private static Logging logging;

	public static void initialise(Logging _logging) {
		System.out.println("init");
		logging = _logging;
	}

	public static void output(String string) {
		if (logging != null) {
			logging.logToOutput(formatString(string));
		} else {
			System.out.println(string);
		}
	}

	public static void outputError(String string) {
		if (logging != null) {
			logging.logToError(formatString(string));
		} else {
			System.err.println(string);
		}
	}

	private static String formatString(String string) {
		Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
		return DATE_FORMAT.format(cal.getTime()) + " | " + string;
	}

}
