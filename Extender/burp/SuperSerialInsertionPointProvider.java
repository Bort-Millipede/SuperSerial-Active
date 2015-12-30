/*
	SuperSerialInsertionPointProvider.java
	
	v0.2 (12/30/2015)
	
	Custom scanner insertion point provider supplying active scanner insertion points for both the JBoss and WebSphere platforms.
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

public class SuperSerialInsertionPointProvider implements IScannerInsertionPointProvider {
	private IExtensionHelpers helpers;
	
	private static final byte JAVA_OBJECT_0 = (byte) 172; //0xAC
	private static final byte JAVA_OBJECT_1 = (byte) 237; //0xED
	private static final byte JAVA_OBJECT_2 = 0x00; //0x00
	private static final byte JAVA_OBJECT_3 = 0x05; //0x05
	private static final String JAVA_64_START = "rO0AB";
	
	public SuperSerialInsertionPointProvider(IExtensionHelpers h) {
		helpers = h;
	}
	
	//IScannerInsertionPointProvider methods
	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
		List<IScannerInsertionPoint> ipl = null;
		byte[] req = baseRequestResponse.getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		int dataStart = reqInfo.getBodyOffset();
		
		//check for request body containing plaintext Java serialized object
		if((req.length-dataStart)>=4) {
			if(req[dataStart] == JAVA_OBJECT_0) {
				if(req[dataStart+1] == JAVA_OBJECT_1) {
					if(req[dataStart+2] == JAVA_OBJECT_2) {
						if(req[dataStart+3] == JAVA_OBJECT_3) { //Java serialized object found in request body: create JBoss insertion point and return
							ipl = new ArrayList<IScannerInsertionPoint>(1);
							ipl.add(new JBossSerializedInsertionPoint(helpers,baseRequestResponse));
							return ipl;
						}
					}
				}
			}
		}
		
		//if Java serialized object not found in request body, search for in response body
		byte[] resp = baseRequestResponse.getResponse();
		IResponseInfo respInfo = helpers.analyzeResponse(resp);
		int respDataStart = respInfo.getBodyOffset();
		if((resp.length-respDataStart)>=4) {
			if(resp[respDataStart] == JAVA_OBJECT_0) {
				if(resp[respDataStart+1] == JAVA_OBJECT_1) {
					if(resp[respDataStart+2] == JAVA_OBJECT_2) {
						if(resp[respDataStart+3] == JAVA_OBJECT_3) { //Java serialized object found in response body: create JBoss insertion point and return
							ipl = new ArrayList<IScannerInsertionPoint>(1);
							ipl.add(new JBossSerializedInsertionPoint(helpers,baseRequestResponse));
							return ipl;
						}
					}
				}
			}
		}
		
		//if no plaintext Java serialized object found, search for base64-encoded parameter value(s) starting with "rO0AB"
		List<IParameter> reqParams = reqInfo.getParameters();
		Iterator<IParameter> paramItr = reqParams.iterator();
		while(paramItr.hasNext()) {
			IParameter param = paramItr.next();
			String paramVal = param.getValue();
			paramVal = helpers.urlDecode(paramVal);
			if((paramVal.length()>=5) && paramVal.substring(0,5).equals(JAVA_64_START)) {
				byte[] paramValDecode = helpers.base64Decode(paramVal);
				if(paramValDecode[0] == JAVA_OBJECT_0) { //check if decoded data is a Java serialized object
					if(paramValDecode[1] == JAVA_OBJECT_1) {
						if(paramValDecode[2] == JAVA_OBJECT_2) {
							if(paramValDecode[3] == JAVA_OBJECT_3) { //decoded data is a Java serialized object: create WebSphere insertion point
								if(ipl==null) ipl = new ArrayList<IScannerInsertionPoint>();
								ipl.add(new WebSphereSerializedInsertionPoint(helpers,baseRequestResponse,param.getName()));
							}
						}
					}
				}
			}
		}
		
		return ipl;
	}
}
