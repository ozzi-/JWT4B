package app.helpers;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class Output {

	private static SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
	
	public static void output(String string) {
		Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
		Config.stdout.println(sdf.format(cal.getTime()) + " | " + string);
	}
	
	public static void outputError(String string) {
		Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
		Config.stderr.println(sdf.format(cal.getTime()) + " | " + string);
	}
}
