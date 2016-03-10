/*
	SuperSerialNode.java
	
	v0.3 (3/10/2016)
	
	Node for SuperSerial Active Scan check to use. The active scan check will first make a GET request to the /queue context which will create a new custom
	context (SuperSerialNodeHttpHandler.java) with a randomly-generated path, which will be returned in a JSON object in the response. The Active Scan check 
	will then attempt to force the target system to access the path and either write an access entry or upload a local file. The Active Scan check will then 
	attempt to download the access entry or uploaded file to confirm the presence of a vulnerability. All access is controlled by requiring all client 
	requests to contain a randomly-generated authentication token GUID as a URL parameter. This GUID is outputted to the console immediately when the node 
	is started, and must be entered into the SuperSerial-Active Scan Settings menu for the check to properly function.
*/

package superserial.node;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.Headers;
import java.net.URI;
import java.net.InetSocketAddress;
import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.security.SecureRandom;
import org.json.JSONObject;

public class SuperSerialNode {
	private HttpServer hs;
	private int port;
	private boolean https;
	private String token;
	private SecureRandom sr;
	private String dir;
	
	private static final String VERSION = "0.3";
	private static final int DEFAULT_PORT = 15050;
	
	public SuperSerialNode(int p) {
		https=false;
		hs = null;
		if((p>=1) && (p<=65535)) {
			port = p;
		} else {
			System.err.println("Invalid port "+Integer.toString(p)+" specified: falling back to default port "+Integer.toString(DEFAULT_PORT));
			port = DEFAULT_PORT;
		}
		try {
			hs = HttpServer.create(new InetSocketAddress(port),0);
		} catch(IOException e) {
			e.printStackTrace();
			return;
		}
		sr = new SecureRandom();
		token = generateGUID();
		
		//create directory to store uploaded files/access entries (if not already created)
		dir = System.getProperty("java.io.tmpdir")+"SuperSerial"+System.getProperty("file.separator");
		File targetDir = new File(dir);
		if(!targetDir.exists()) {
			targetDir.mkdir();
		}
		
		hs.createContext("/queue",new QueueHandler());
		hs.createContext("/heartbeat",new HeartbeatHandler());
		hs.start();
	}
	
	private void printSessionInfo() {
		System.err.println("SuperSerial Node v"+VERSION);
		System.err.println("Uploaded File/Access Entry Directory: "+dir);
		System.err.println("Node started on HTTP"+(https ? "S" : "")+" port "+port);
		System.err.println("Node Authentication Token for this session: "+token);
	}
	
	//dynamically create new context when requested
	private void createContext(String path) {
		if(path.charAt(0)!='/') path = "/"+path;
		hs.createContext(path,new SuperSerialNodeHttpHandler(token,path));
	}
	
	//convert byte array to hexadecimal string
	private String bytesToHex(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length*2];
		for(int j=0;j<bytes.length;j++){
			int v =bytes[j] & 0xFF;
			hexChars[j*2]=hexArray[v>>>4];
			hexChars[j*2+1]=hexArray[v&0x0F];
		}
		return new String(hexChars);
    }
	
	private String generateGUID() {
		String retVal = generateRandom(16);
		return retVal.substring(0,8)+"-"+retVal.substring(8,12)+"-"+retVal.substring(12,16)+"-"+retVal.substring(16,20)+"-"+retVal.substring(20);
	}
	
	private String generateShortRandom() {
		return generateRandom(5);
	}
	
	private String generateRandom(int l) {
		byte[] buffer = new byte[l];
		sr.nextBytes(buffer);
		return bytesToHex(buffer);
	}
	
	//handler for /queue context: create new context when requested, return path to created context JSON body (requires authentication token GUID)
	private class QueueHandler implements HttpHandler {
		public void handle(HttpExchange exchange) {
			try {
				OutputStream os = null;
				if(exchange.getRequestMethod().equalsIgnoreCase("GET")) {
					URI uri = exchange.getRequestURI();
					String clientToken = null;
					
					Hashtable<String,String> urlParams = SuperSerialNodeHelper.parseURLParams(uri.getQuery());
					if((urlParams!=null) && urlParams.containsKey("token")) {
						clientToken = urlParams.get("token");
					}
					
					if(token.equalsIgnoreCase(clientToken)) { //valid request: create handler and return URL
						exchange.getRequestBody().close();
						String context = "/"+generateShortRandom();
						createContext(context);
						JSONObject jsonObj = new JSONObject();
						jsonObj.put("path",context);
						String jsonReturn = jsonObj.toString(); //return newly created path as JSON parameter
						Headers respHeaders = exchange.getResponseHeaders();
						respHeaders.add("Content-Type","application/json");
						exchange.sendResponseHeaders(200,jsonReturn.length());
						os = exchange.getResponseBody();
						os.write(jsonReturn.getBytes());
						os.flush();
						os.close();
						SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" succeeded, "+context+" context added!");
					} else {
						SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong authentication token)");
						exchange.sendResponseHeaders(401,-1);
						os = exchange.getResponseBody();
						os.close();
					}
				} else {
					SuperSerialNodeHelper.printLogEntry("Queue request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong HTTP method)");
					exchange.sendResponseHeaders(405,-1);
					os = exchange.getResponseBody();
					os.close();
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}
	
	//handler for /heartbeat context: check connection to node (requires authentication token GUID)
	private class HeartbeatHandler implements HttpHandler {
		public void handle(HttpExchange exchange) {
			try {
				//Headers reqHeaders = exchange.getRequestHeaders();
				URI uri = exchange.getRequestURI();
				String clientToken = null;
				
				Hashtable<String,String> urlParams = SuperSerialNodeHelper.parseURLParams(uri.getQuery());
				if((urlParams!=null) && urlParams.containsKey("token")) {
					clientToken = urlParams.get("token");
				}
				
				if(token.equalsIgnoreCase(clientToken)) { //valid request: return HTTP 200 to confirm that connection was successful
					JSONObject jsonObj = new JSONObject();
					//TODO: put Node version information in here (for extender verification purposes)
					jsonObj.put("message","I\'m SuperSerial");
					String jsonReturn = jsonObj.toString(); //return newly created path as JSON parameter
					Headers respHeaders = exchange.getResponseHeaders();
					respHeaders.add("Content-Type","application/json");
					exchange.sendResponseHeaders(200,jsonReturn.length());
					OutputStream os = exchange.getResponseBody();
					os.write(jsonReturn.getBytes());
					os.flush();
					os.close();
					SuperSerialNodeHelper.printLogEntry("Heartbeat request from "+exchange.getRemoteAddress().getHostString()+" succeeded");
				} else {
					exchange.sendResponseHeaders(401,-1);
					exchange.getResponseBody().close();
					SuperSerialNodeHelper.printLogEntry("Heartbeat request from "+exchange.getRemoteAddress().getHostString()+" denied (wrong authentication token)");
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}
	
	public static void main(String[] args) {
		int p = DEFAULT_PORT;
		if(args.length>0){
			try {
				p = Integer.parseInt(args[0]);
			} catch(Exception e) {
				System.err.println("Invalid port \'"+args[0]+"\' specified: falling back to default port "+Integer.toString(DEFAULT_PORT));
			}
		}
		SuperSerialNode node = null;
		node = new SuperSerialNode(p);
		node.printSessionInfo();	
	}
}
