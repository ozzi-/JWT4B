package app.helpers;

import java.io.IOException;
import java.util.Arrays;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter.Indenter;

// we need this so we don't have to include a whole jackson lib,
// as parts of it are implicitly included by other libraries used
// Code comes from https://github.com/codehaus/jackson/blob/master/src/java/org/codehaus/jackson/util/DefaultPrettyPrinter.java
// changed some stuff so we can get an instance from it
public class Lf2SpacesIndenter implements Indenter {
	final static String SYSTEM_LINE_SEPARATOR;

	private static Lf2SpacesIndenter instance = null;

	public static Lf2SpacesIndenter getInstance() {
		if (instance == null) {
			instance = new Lf2SpacesIndenter();
		}
		return instance;
	}

	static {
		String lf = null;
		try {
			lf = System.getProperty("line.separator");
		} catch (Throwable t) {
		} // access exception?
		SYSTEM_LINE_SEPARATOR = (lf == null) ? "\n" : lf;
	}

	final static int SPACE_COUNT = 64;
	final static char[] SPACES = new char[SPACE_COUNT];
	static {
		Arrays.fill(SPACES, ' ');
	}

	public Lf2SpacesIndenter() {
	}

	// @Override
	public boolean isInline() {
		return false;
	}

	// @Override
	public void writeIndentation(JsonGenerator jg, int level) throws IOException, JsonGenerationException {
		jg.writeRaw(SYSTEM_LINE_SEPARATOR);
		if (level > 0) {
			level += level; // 2 spaces per level
			while (level > SPACE_COUNT) { // should never happen but...
				jg.writeRaw(SPACES, 0, SPACE_COUNT);
				level -= SPACES.length;
			}
			jg.writeRaw(SPACES, 0, level);
		}
	}
}