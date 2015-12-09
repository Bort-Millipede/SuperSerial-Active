# SuperSerial-Active
SuperSerial-Active - Java Deserialization Vulnerability Active Identification Burp Extender

See Blog: https://www.directdefense.com/superserial-active-java-deserialization-active-identification-burp-extender/

To help our customers and readers definitively identify Java Deserialization vulnerabilities, we have created an additional Burp Suite Extender called “SuperSerial-Active” to compliment our previous release of "SuperSerial-Passive" (https://github.com/DirectDefense/SuperSerial) . Unlike the previous extender, which only passively identifies potential instances of Java deserialization vulnerabilities, this extender actively attempts to exploit the vulnerability in a non-intrusive way. This results in the confirmed identification of a deserialization vulnerability. The Extender currently tests only against target systems running the JBoss platform, but can detect the vulnerability on both Linux and Windows systems running JBoss. Support for detecting the vulnerability on systems running WebSphere will be added in future releases of the extender.

Extender Overview
SuperSerial-Active consists of two components, an extender to be loaded into Burp Suite Professional (superserial-active-[VERSION].jar) and a standalone web server node written entirely in Java (SuperSerialNode-[VERSION].jar). The extender works by sending a request containing a serialized object exploit payload from the Burp Suite Active Scanner to the target system. The payload contains a single operating system command that is intended to be executed by the target system (both Linux and Windows commands are attempted), specifically to have the target system a) access the SuperSerial Node via HTTP, or b) upload a local file to the SuperSerial Node via HTTP. After sending the exploit payload, the extender then communicates with the SuperSerial Node via HTTP to determine whether the node was accessed by the target system, or if a file was uploaded by the target system. If the Node communicates that either of these events has taken place, the extender then creates a new Scan Issue in Burp to confirm the vulnerability to the user.

Extender Configuration/Usage:
1. Decide where the SuperSerial Node will be hosted.
	--the Node must be accessible directly by the target system (if target system is internet-facing, the node must be hosted with an internet-facing IP address or registered domain name).
	--the Node can be hosted on the same machine that is running Burp Suite, as long as the target system can access it directly.
	--the system running the Node must have the Java Runtime Environment 7 or higher installed.
2. Download the superserial-active-[VERSION].jar file on the machine running Burp Suite, and the SuperSerialNode-[VERSION].jar file on the system that will host the Node.
3. Open a terminal and launch the SuperSerial Node with the command: java -jar SuperSerialNode-[VERSION].jar
	--The Node listens on port 15050 by default. To have the node listen on another port, include a command line argument specifying what port the node will listen on (ex. java -jar SuperSerialNode.jar 8090).
4. The Node will print some information to the console after it has successfully launched. Take note of the Node Authentication Token that is printed to the terminal.
5. Load the superserial-active-[VERSION].jar file into Burp in the Extender tab. The SuperSerial-Active extender will be loaded but will need to be configured before it can be used.
6. Configure extender in the SuperSerial tab.
	a. Set the Node host. It must be set as the domain name or IP address that the target system will use to access the Node
		--Note: If the Node is hosted on the same machine as burp is running, the host must be set to the IP address of this machine, NOT TO 127.0.0.1!
	b. Set the Node port (the port the Node is listening on)
	c. Set the Node Token, which was printed to the console of the SuperSerial Node when it was launched.
	d. Click "Test Connection" and verify that the status pane indicates a successful connection, or change the settings based on the status pane message.
	e. Configure download attempts and wait time:
		--After sending the serialized object exploit payload the extender accesses the node a maximum number of tries (5 by default), waiting a specified amount of time between each try (1.5 seconds by default). Setting low values will allow the Active Scanner to finish more quickly but will increase the likelyhood of failing to detect the vulnerability, therefore higher values are recommended.
7. Change filters in the Proxy and Target tabs to display "Other Binary". This will ensure any Scan Issues created by the extender will be displayed to the user.
8. Perform an active scan against any suspected vulnerable URLs. Additionally, the user can view the console output of the SuperSerial Node during the scan to view messages indicating any communication with the Node as it occurs, as well as to diagnose any potential issues.
9. If a vulnerability is detected by the SuperSerial-Active extender, a new "Java Deserialization Vulnerability" Scan Issue will be created in Burp Suite. 

Extender Dependencies:
--YSoSerial (for creating serialized object exploit payloads): https://github.com/frohoff/ysoserial (included in release superserial-active-[VERSION].jar file)
--JSON for Java (for properly creating and parsing JSON in extender and Node): https://github.com/douglascrockford/JSON-java (included in release superserial-active-[VERSION].jar and SuperSerialNode-[VERSION].jar files)

Extender Building Instructions:
COMING SOON!

Extender written by Jeff Cap

Disclaimer:
This software is only intended to be used against systems the user explicitly owns or has authorization to test/attack. The developers provide the software for free without warranty, and assume no responsibility for any damage caused to systems by misusing the software. It is the responsibility of the user to abide by all local, state and federal laws while using the software.

License:
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
