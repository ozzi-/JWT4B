package app.helpers;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Output {

	private static Calendar cal = Calendar.getInstance();
	private static SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

	public static void output(String string) {
		Config.stdout.println(sdf.format(cal.getTime()) + " | " + string);
	}
	
	public static void outputError(String string) {
		Config.stderr.println(sdf.format(cal.getTime()) + " | " + string);
	}
}
