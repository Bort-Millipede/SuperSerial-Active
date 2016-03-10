# SuperSerial-Active
SuperSerial-Active - Java Deserialization Vulnerability Active Identification Burp Extender

See Blog: https://www.directdefense.com/superserial-active-java-deserialization-active-identification-burp-extender/

To help our customers and readers definitively identify Java Deserialization vulnerabilities, we have created an additional Burp Suite Extender called “SuperSerial-Active” to compliment our previous release of "SuperSerial-Passive" (https://github.com/DirectDefense/SuperSerial) . Unlike the previous extender, which only passively identifies potential instances of Java deserialization vulnerabilities, this extender actively attempts to exploit the vulnerability in a non-intrusive way. This results in the confirmed identification of a deserialization vulnerability. The Extender currently tests only against target systems running the JBoss or WebSphere platforms, but can detect the vulnerability on both Linux and Windows systems running JBoss or WebSphere. Support for detecting the vulnerability on systems running other platforms will be added in future releases of the extender.

## Extender Overview
SuperSerial-Active consists of two components, an extender to be loaded into Burp Suite Professional (superserial-active-[VERSION].jar) and a standalone web server node written entirely in Java (SuperSerialNode-[VERSION].jar). The extender works by sending a request containing a serialized object exploit payload from the Burp Suite Active Scanner to the target system. The payload contains a single operating system command that is intended to be executed by the target system (both Linux and Windows commands are attempted), specifically to have the target system access the SuperSerial Node via HTTP, or upload a local file to the SuperSerial Node via HTTP. After sending the exploit payload, the extender then communicates with the SuperSerial Node via HTTP to determine whether the node was accessed by the target system, or if a file was uploaded by the target system. If the Node communicates that either of these events has taken place, the extender then creates a new Scan Issue in Burp Suite to confirm the vulnerability to the user.

## Extender Configuration/Usage:

1. Decide where the SuperSerial Node will be hosted.

	* the Node must be accessible directly by the target system (if target system is internet-facing, the node must be hosted with an internet-facing IP address or registered domain name).

	* the Node can be hosted on the same machine that is running Burp Suite, as long as the target system can access it directly.

	* the system running the Node must have Java Runtime Environment 7 or higher installed.

2. Download the superserial-active-[VERSION].jar file on the machine running Burp Suite, and the SuperSerialNode-[VERSION].jar file on the system that will host the Node.

3. Open a terminal and launch the SuperSerial Node with the command: java -jar SuperSerialNode-[VERSION].jar

	* The Node listens on port 15050 by default. To have the node listen on another port, include a command line argument specifying what port the node will listen on (ex. java -jar SuperSerialNode.jar 8090).

4. The Node will print some information to the console after it has successfully launched. Take note of the Node Authentication Token that is printed to the terminal.

5. Load the superserial-active-[VERSION].jar file into Burp in the Extender tab. The SuperSerial-Active extender will be loaded but will need to be configured before it can be used.

6. Configure Node connection settings in the SuperSerial->"Node Connection Settings" tab.

	a. Set the Node Host. It must be set as the domain name or IP address that the target system will use to access the Node

		* Note: If the Node is hosted on the same machine as burp is running, the Node Host must be set to the IP address of this machine, NOT TO 127.0.0.1!

	b. Set the Node Port (the port the Node is listening on)

	c. Set the Node Token, which was printed to the console of the SuperSerial Node when it was launched.

	d. Click "Test Connection" and verify that the status pane indicates a successful connection, or change the settings based on the status pane message.

7. Configure Active Scan settings in the SuperSerial->"Scan Settings" tab.

	a. If desired, set the "Scan All" setting to scan all request parameters during active scanning.
		
		* WARNING: This will GREATLY increase the overall scan time per URL. Only enable this setting if needed.
	
	b. Configure download attempts and wait time:

		* After sending the serialized object exploit payload the extender accesses the node a maximum number of tries (5 by default), waiting a specified amount of time between each try (1.5 seconds by default).
		* Setting low values will allow the Active Scanner to finish more quickly but will increase the likelyhood of failing to detect the vulnerability, therefore higher values are recommended.
	
	c. Review the operating system commands listed that will be used during Active Scanning.
		
		* Additional commands can be added to the list that will be used during scanning. In order to detect the vulnerability, the added command must force the target system to access the Node via HTTP. Additional details about adding new commands coming soon!
		* Commands are used during active scanning in the order they are listed in the table (top to bottom). 
	
8. Change filters in the Proxy and Target tabs to display "Other Binary". This will ensure any Scan Issues created by the extender will be displayed to the user.

9. Perform an active scan against any suspected vulnerable URLs. Additionally, the user can view the console output of the SuperSerial Node during the scan to view messages indicating any communication with the Node as it occurs, as well as to diagnose any potential issues.

10. If a vulnerability is detected by the SuperSerial-Active extender, a new "Java Deserialization Vulnerability" Scan Issue will be created in Burp Suite. 

## Extender Dependencies:

* YSoSerial (for creating serialized object exploit payloads): https://github.com/frohoff/ysoserial (included in release superserial-active-[VERSION].jar file, v0.0.2 at time of writing)

* JSON for Java (for properly creating and parsing JSON in extender and Node): https://github.com/douglascrockford/JSON-java (included in release superserial-active-[VERSION].jar and SuperSerialNode-[VERSION].jar files, version 20151123 at time of writing)

## Extender Building Instructions:
Requires Java Development Kit 7 or higher

1. Choose folder to use for building (these instructions will use c:\test)

2. Create the following directories (case-sensitive):

	* c:\test\api
	
	* c:\test\build-extender
	
	* c:\test\build-node
	
3. Download the SuperSerial-Active master source zip and extract to folder c:\test (SuperSerial-Active-master folder and subfolders will be created)

4. Download the Burp Extender interface files

	a. Launch Burp Suite and navigate to the Extender->APIs tab
	
	b. Click 'Save interface files' button
	
	c. In the save prompt, navigate to c:\test\api and click 'Save'
	
5. Create directory (case sensitive): c:\test\api\org

6. Download "JSON for Java" (https://github.com/douglascrockford/JSON-java) master source zip and extract to folder: c:\test\api\org

7. Rename newly extracted folder (JSON-java-[version]) to (case-sensitive): json

8. Copy all contents of c:\test\api into: c:\test\SuperSerial-Active\Extender, overwrite any duplicate files

9. Copy folder c:\test\api\org into: c:\test\SuperSerial-Active\Node, overwrite any duplicate files

10. Remove folder c:\test\api, it is no longer needed

11. Download ysoserial (https://github.com/frohoff/ysoserial) release jar (ysoserial-0.0.2-all.jar at time of writing) to c:\test

12. Extract ysoserial jar to c:\test\build-extender folder:

	a. In a terminal window, navigate to c:\test\build-extender
	
	b. Execute command: jar xvf ../ysoserial-[release].jar
	
13. To build the SuperSerial-Active Extender, do the following (this will create file c:\test\superserial-active.jar):

	a. In a terminal window, navigate to c:\test
	
	b. execute command: javac -cp build-extender -d build-extender -sourcepath SuperSerial-Active-master/Extender SuperSerial-Active-master/Extender/burp/*.java SuperSerial-Active-master/Extender/superserial/settings/*.java SuperSerial-Active-master/Extender/superserial/ui/*.java SuperSerial-Active-master/Extender/ysoserial/*.java
	
	c. execute command: jar vcf superserial-active.jar -C build-extender . -C SuperSerial-Active-master/Extender licenses/JSON-LICENSE.txt -C SuperSerial-Active-master/Extender licenses/YSOSERIAL-LICENSE.txt
	
14. To build the SuperSerial Node, do the following (this will create file c:\test\SuperSerialNode.jar):

	a. In a terminal window, navigate to c:\test
	
	b. execute command: javac -d build-node -sourcepath SuperSerial-Active-master/Node SuperSerial-Active-master/Node/superserial/node/*.java
	
	c. execute command: jar vcfm SuperSerialNode.jar SuperSerial-Active-master/Node/MF.TXT -C build-node . -C SuperSerial-Active-master/Node JSON-LICENSE.txt


## Disclaimer:
This software is only intended to be used against systems the user explicitly owns or has authorization to test/attack. The developers provide the software for free without warranty, and assume no responsibility for any damage caused to systems by misusing the software. It is the responsibility of the user to abide by all local, state and federal laws while using the software.

## License:
Extender written by Jeff Cap
Copyright (C) 2015 DirectDefense, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
