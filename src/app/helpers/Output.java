package app.helpers;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class Output {

	private static SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
	
	public static void output(String string) {
		Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
		String msg = sdf.format(cal.getTime()) + " | " + string;
		if(Config.stdout==null) {
			System.out.println(msg);
		}else {
			Config.stdout.println(msg);			
		}
	}
	
	public static void outputError(String string) {
		Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
		String msg = sdf.format(cal.getTime()) + " | " + string;
		if(Config.stderr==null) {
			System.err.println(msg);
		}else {
			Config.stderr.println(msg);			
		}
	}
}
