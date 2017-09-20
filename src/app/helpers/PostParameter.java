package app.helpers;

public class PostParameter {
	private String name;
	private String value;
	private int from;
	private int to;
	
	public PostParameter(String name, String value, int from , int to) {
		this.setName(name);
		this.setValue(value);
		this.setFrom(from);
		this.setTo(to);
	}
	
	public String getName() {
		return name;
	}
	public String getNameAsParam() {
		return name+"=";
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public int getFrom() {
		return from;
	}
	public void setFrom(int from) {
		this.from = from;
	}
	public int getTo() {
		return to;
	}
	public void setTo(int to) {
		this.to = to;
	}
}
