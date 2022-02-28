package app.helpers;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class Output {
    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

    private static PrintWriter stdout = new PrintWriter(System.out, true);
    private static PrintWriter stderr = new PrintWriter(System.err, true);

    public static void initialise(OutputStream outputStream, OutputStream errorStream) {
        stdout = new PrintWriter(outputStream, true);
        stderr = new PrintWriter(errorStream, true);
    }

    public static void output(String string) {
        write(stdout, string);
    }

    public static void outputError(String string) {
        write(stderr, string);
    }

    private static void write(PrintWriter writer, String string) {
        Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
        String msg = DATE_FORMAT.format(cal.getTime()) + " | " + string;
        writer.println(msg);
    }
}
