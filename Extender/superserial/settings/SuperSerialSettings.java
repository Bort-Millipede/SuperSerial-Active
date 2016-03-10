/*
	SuperSerialSettings.java
	
	v0.3 (3/10/2016)
	
	Maintains the global settings utilized by the SuperSerial-Active extender in various areas. Includes Node connection settings and Active Scan related settings.
*/

package superserial.settings;

public class SuperSerialSettings {
	private static SuperSerialSettings settings = null;
	
	//node setting fields
	private String nodeHost;
	private int nodePort;
	private boolean nodeHttps;
	private String nodeToken;
	
	//scan setting fields
	private int downloadTries;
	private int waitTime;
	private boolean scanAll;
	
	//constants
	private static final int DEFAULT_DOWNLOAD_TRIES = 5;
	private static final int DEFAULT_DOWNLOAD_WAIT_TIME = 1500;
	
	//default constructor
	private SuperSerialSettings() {
		nodeHost = null;
		nodePort = -1;
		nodeHttps = false;
		nodeToken = null;
		
		downloadTries = DEFAULT_DOWNLOAD_TRIES;
		waitTime = DEFAULT_DOWNLOAD_WAIT_TIME;
		scanAll = false;
	}
	
	//get SuperSerialSettings instance for use elsewhere
	public static SuperSerialSettings getInstance() {
		if(settings==null) {
			settings = new SuperSerialSettings();
		}
		return settings;
	}
	
	//reset all settings back to default
	public static SuperSerialSettings resetSettings() {
		settings = new SuperSerialSettings();
		return settings;
	}
	
	//set settings pertaining to Node connection
	public void setNodeSettings(String host,int port,boolean https,String token) {
		nodeHost = host;
		nodePort = port;
		nodeHttps = https;
		nodeToken = token;
	}
	
	//set settings pertaining to Active Scanner
	public void setScanSettings(int dt,int wt,boolean sa) {
		downloadTries = dt;
		waitTime = wt;
		scanAll = sa;
	}
	
	
	//node connection settings accessors
	//get node host
	public String getNodeHost() {
		return nodeHost;
	}
	
	//get node listening port
	public int getNodePort() {
		return nodePort;
	}
	
	//get node protocol (false: HTTP, true: HTTPS)
	public boolean getNodeHttps() {
		return nodeHttps;
	}
	
	//get node protocol as String
	public String getNodeHttpsStr() {
		String retVal = "http";
		if(nodeHttps) retVal += "s";
		return retVal;
	}
	
	//get node authentication token
	public String getNodeToken() {
		return nodeToken;
	}
	
	
	//scan settings accessors
	//get number of Node download/access attempts used during Active Scan
	public int getDownloadTries() {
		return downloadTries;
	}
	
	//get wait time between Node download/access attempts used during Active Scan
	public int getWaitTime() {
		return waitTime;
	}
	
	//get Scan All setting (whether to skip insertion point creation analysis and instead automatically create insertion points for JBoss and all natively-listed request parameters)
	public boolean getScanAll() {
		return scanAll;
	}
}
