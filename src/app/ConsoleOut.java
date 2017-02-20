package app;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class ConsoleOut {
	
	
    static Calendar cal = Calendar.getInstance();
    static SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

	public static void output(String string){
		if(Settings.output){
			System.out.println( sdf.format(cal.getTime())+" | "+string);
		}
	}
}
