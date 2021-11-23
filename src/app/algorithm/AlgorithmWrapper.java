package app.algorithm;

public class AlgorithmWrapper {
	private final String algorithm;
	private final String type;

	public AlgorithmWrapper(String algorithm, String none) {
		this.algorithm = algorithm;
		this.type = none;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getType() {
		return type;
	}
}
