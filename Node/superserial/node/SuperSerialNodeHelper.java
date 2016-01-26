/*
	SuperSerialNodeHelper.java
	
	//PUT CORRECT VERSION/DATE HERE
	v0.2.1 (1/25/2016)
	
	Class containing static methods to assist in various aspects of processing throughout the SuperSerial node.
*/

package superserial.node;

import java.util.*;
import java.text.SimpleDateFormat;

public class SuperSerialNodeHelper {
	
	//parses URL parameters (token and write), DOES NOT support multiple parameters of same name (only first occurrence from left will be used)
	public static Hashtable<String,String> parseURLParams(String query) {
		Hashtable<String,String> params = null;
		if(query!=null) {
			params = new Hashtable<String,String>(2);
			String[] paramsList = query.split("&");
			for(int i=0;i<paramsList.length;i++) {
				if(paramsList[i].indexOf('=')>=0) {
					String[] paramSplit = paramsList[i].split("=",2);
					String paramName = paramSplit[0];
					
					if(paramName.equalsIgnoreCase("token")) {
						if(!params.containsKey("token")) { //check if param was already found
								params.put(paramName,paramSplit[1]);
						}
					} else if(paramName.equalsIgnoreCase("write")) {
						if(!params.containsKey("write")) {
							params.put(paramName,paramSplit[1]);
						}
					}
				}
			}
		}
		return params;
	}
	
	public static void printLogEntry(String message) {
		Date now = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
		System.err.println(sdf.format(now)+": "+message);
	}
}
