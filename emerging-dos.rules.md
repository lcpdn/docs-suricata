# 2009701
`#alert udp any any -> any 53 (msg:"ET DOS DNS BIND 9 Dynamic Update DoS attempt"; byte_test:1,&,40,2; byte_test:1,>,0,5; byte_test:1,>,0,1; content:"|00 00 06|"; offset:8; content:"|c0 0c 00 ff|"; distance:2; reference:cve,2009-0696; reference:url,doc.emergingthreats.net/2009701; classtype:attempted-dos; sid:2009701; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **DNS BIND 9 Dynamic Update DoS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2009-0696|url,doc.emergingthreats.net/2009701

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010817
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET DOS Possible Cisco ASA 5500 Series Adaptive Security Appliance Remote SIP Inspection Device Reload Denial of Service Attempt"; flow:established,to_server; content:"REGISTER"; depth:8; nocase; isdataat:400,relative; pcre:"/REGISTER.{400}/smi"; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=19915; reference:cve,2010-0569; reference:url,doc.emergingthreats.net/2010817; classtype:attempted-dos; sid:2010817; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Cisco ASA 5500 Series Adaptive Security Appliance Remote SIP Inspection Device Reload Denial of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,tools.cisco.com/security/center/viewAlert.x?alertId=19915|cve,2010-0569|url,doc.emergingthreats.net/2010817

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000011
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"ET DOS Catalyst memory leak attack"; flow: to_server,established; content:"|41 41 41 0a|"; depth: 20; reference:url,www.cisco.com/en/US/products/products_security_advisory09186a00800b138e.shtml; reference:url,doc.emergingthreats.net/bin/view/Main/2000011; classtype:attempted-dos; sid:2000011; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Catalyst memory leak attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.cisco.com/en/US/products/products_security_advisory09186a00800b138e.shtml|url,doc.emergingthreats.net/bin/view/Main/2000011

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002843
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 1755 (msg:"ET DOS Microsoft Streaming Server Malformed Request"; flow:established,to_server; content:"MSB "; depth:4; content:"|06 01 07 00 24 00 00 40 00 00 00 00 00 00 01 00 00 00|"; distance:0; within:18; reference:bugtraq,1282; reference:url,www.microsoft.com/technet/security/bulletin/ms00-038.mspx; reference:url,doc.emergingthreats.net/bin/view/Main/2002843; classtype:attempted-dos; sid:2002843; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Streaming Server Malformed Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,1282|url,www.microsoft.com/technet/security/bulletin/ms00-038.mspx|url,doc.emergingthreats.net/bin/view/Main/2002843

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001795
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET DOS Excessive SMTP MAIL-FROM DDoS"; flow: to_server, established; content:"MAIL FROM|3a|"; nocase; window: 0; id:0; threshold: type limit, track by_src, count 30, seconds 60; reference:url,doc.emergingthreats.net/bin/view/Main/2001795; classtype:denial-of-service; sid:2001795; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Excessive SMTP MAIL-FROM DDoS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001795

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010491
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt"; flow:to_server,established; content:"SELECT"; nocase; content:"geometrycollectionfromwkb"; distance:0; nocase; pcre:"/SELECT.+geometrycollectionfromwkb/si"; reference:url,www.securityfocus.com/bid/37297/info; reference:url,marc.info/?l=oss-security&m=125881733826437&w=2; reference:url,downloads.securityfocus.com/vulnerabilities/exploits/37297.txt; reference:cve,2009-4019; reference:url,doc.emergingthreats.net/2010491; classtype:attempted-dos; sid:2010491; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible MYSQL GeomFromWKB() function Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.securityfocus.com/bid/37297/info|url,marc.info/?l=oss-security&m=125881733826437&w=2|url,downloads.securityfocus.com/vulnerabilities/exploits/37297.txt|cve,2009-4019|url,doc.emergingthreats.net/2010491

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010492
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET DOS Possible MYSQL SELECT WHERE to User Variable Denial Of Service Attempt"; flow:to_server,established; content:"SELECT"; nocase; content:"WHERE"; distance:0; nocase; content:"SELECT"; nocase; content:"INTO"; distance:0; nocase; content:"|60|"; within:50; content:"|60|"; pcre:"/SELECT.+WHERE.+SELECT.+\x60/si"; reference:url,www.securityfocus.com/bid/37297/info; reference:url,marc.info/?l=oss-security&m=125881733826437&w=2; reference:url,downloads.securityfocus.com/vulnerabilities/exploits/37297-2.txt; reference:cve,2009-4019; reference:url,doc.emergingthreats.net/2010492; classtype:attempted-dos; sid:2010492; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible MYSQL SELECT WHERE to User Variable Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.securityfocus.com/bid/37297/info|url,marc.info/?l=oss-security&m=125881733826437&w=2|url,downloads.securityfocus.com/vulnerabilities/exploits/37297-2.txt|cve,2009-4019|url,doc.emergingthreats.net/2010492

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011761
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET DOS Possible MySQL ALTER DATABASE Denial Of Service Attempt"; flow:established,to_server; content:"ALTER "; nocase; content:"DATABASE"; nocase; within:12; content:"|22|."; distance:0; content:"UPGRADE "; nocase; distance:0; content:"DATA"; nocase; within:8; pcre:"/ALTER.+DATABASE.+\x22\x2E(\x22|\x2E\x22|\x2E\x2E\x2F\x22).+UPGRADE.+DATA/si"; reference:url,securitytracker.com/alerts/2010/Jun/1024160.html; reference:url,dev.mysql.com/doc/refman/5.1/en/alter-database.html; reference:cve,2010-2008; reference:url,doc.emergingthreats.net/2011761; classtype:attempted-dos; sid:2011761; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible MySQL ALTER DATABASE Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,securitytracker.com/alerts/2010/Jun/1024160.html|url,dev.mysql.com/doc/refman/5.1/en/alter-database.html|cve,2010-2008|url,doc.emergingthreats.net/2011761

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010486
`#alert udp $EXTERNAL_NET 123 -> $HOME_NET 123 (msg:"ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 request)"; dsize:1; content:"|17|"; threshold:type limit, count 1, seconds 60, track by_src; reference:url,www.kb.cert.org/vuls/id/568372; reference:cve,2009-3563; reference:url,doc.emergingthreats.net/2010486; classtype:attempted-dos; sid:2010486; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential Inbound NTP denial-of-service attempt (repeated mode 7 request)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.kb.cert.org/vuls/id/568372|cve,2009-3563|url,doc.emergingthreats.net/2010486

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010487
`#alert udp $EXTERNAL_NET 123 -> $HOME_NET 123 (msg:"ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 reply)"; dsize:4; content:"|97 00 00 00|"; threshold:type limit, count 1, seconds 60, track by_src; reference:url,www.kb.cert.org/vuls/id/568372; reference:cve,2009-3563; reference:url,doc.emergingthreats.net/2010487; classtype:attempted-dos; sid:2010487; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential Inbound NTP denial-of-service attempt (repeated mode 7 reply)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.kb.cert.org/vuls/id/568372|cve,2009-3563|url,doc.emergingthreats.net/2010487

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011673
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"ET DOS Possible SolarWinds TFTP Server Read Request Denial Of Service Attempt"; content:"|00 01 01|"; depth:3; content:"NETASCII"; reference:url,www.exploit-db.com/exploits/12683/; reference:url,doc.emergingthreats.net/2011673; classtype:attempted-dos; sid:2011673; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible SolarWinds TFTP Server Read Request Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.exploit-db.com/exploits/12683/|url,doc.emergingthreats.net/2011673

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011674
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"ET DOS SolarWinds TFTP Server Long Write Request Denial Of Service Attempt"; content:"|00 02|"; depth:2; isdataat:1000,relative; content:!"|0A|"; within:1000; content:"NETASCII"; distance:1000; reference:url,www.exploit-db.com/exploits/13836/; reference:url,doc.emergingthreats.net/2011674; classtype:attempted-dos; sid:2011674; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SolarWinds TFTP Server Long Write Request Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.exploit-db.com/exploits/13836/|url,doc.emergingthreats.net/2011674

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011732
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 5900 (msg:"ET DOS Possible VNC ClientCutText Message Denial of Service/Memory Corruption Attempt"; flow:established,to_server; content:"|06|"; depth:1; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:url,www.fortiguard.com/encyclopedia/vulnerability/vnc.server.clientcuttext.message.memory.corruption.html; reference:url,doc.emergingthreats.net/2011732; classtype:attempted-dos; sid:2011732; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible VNC ClientCutText Message Denial of Service/Memory Corruption Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.fortiguard.com/encyclopedia/vulnerability/vnc.server.clientcuttext.message.memory.corruption.html|url,doc.emergingthreats.net/2011732

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011511
`#alert tcp any any -> $HOME_NET 3000 (msg:"ET DOS ntop Basic-Auth DOS inbound"; flow:established,to_server; content:"GET "; nocase; depth:4; content:"/configNtop.html"; distance:0; within:20; nocase; content:"Authorization|3a|"; nocase; content: "Basic"; distance:0; within:20; content:"=="; distance:0; within:100; reference:url,www.securityfocus.com/bid/36074; reference:url,www.securityfocus.com/archive/1/505862; reference:url,www.securityfocus.com/archive/1/505876; classtype:denial-of-service; sid:2011511; rev:1; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **ntop Basic-Auth DOS inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.securityfocus.com/bid/36074|url,www.securityfocus.com/archive/1/505862|url,www.securityfocus.com/archive/1/505876

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011512
`#alert tcp $HOME_NET any -> any 3000 (msg:"ET DOS ntop Basic-Auth DOS outbound"; flow:established,to_server; content:"GET "; nocase; depth:4; content:"/configNtop.html"; distance:0; within:20; nocase; content:"Authorization|3a|"; nocase; content: "Basic"; distance:0; within:20; content:"=="; distance:0; within:100; reference:url,www.securityfocus.com/bid/36074; reference:url,www.securityfocus.com/archive/1/505862; reference:url,www.securityfocus.com/archive/1/505876; classtype:denial-of-service; sid:2011512; rev:1; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **ntop Basic-Auth DOS outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.securityfocus.com/bid/36074|url,www.securityfocus.com/archive/1/505862|url,www.securityfocus.com/archive/1/505876

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010755
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 6014 (msg:"ET DOS IBM DB2 kuddb2 Remote Denial of Service Attempt"; flow:established,to_server; content:"|00 05 03 31 41|"; reference:url,www.securityfocus.com/bid/38018; reference:url,intevydis.blogspot.com/2010/01/ibm-db2-97-kuddb2-dos.html; reference:url,doc.emergingthreats.net/2010755; classtype:attempted-dos; sid:2010755; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IBM DB2 kuddb2 Remote Denial of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.securityfocus.com/bid/38018|url,intevydis.blogspot.com/2010/01/ibm-db2-97-kuddb2-dos.html|url,doc.emergingthreats.net/2010755

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000010
`#alert udp $EXTERNAL_NET any -> $HOME_NET 514 (msg:"ET DOS Cisco 514 UDP flood DoS"; content:"|25 25 25 25 25 58 58 25 25 25 25 25|"; reference:url,www.cisco.com/warp/public/707/IOS-cbac-dynacl-pub.shtml; reference:url,doc.emergingthreats.net/bin/view/Main/2000010; classtype:attempted-dos; sid:2000010; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco 514 UDP flood DoS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.cisco.com/warp/public/707/IOS-cbac-dynacl-pub.shtml|url,doc.emergingthreats.net/bin/view/Main/2000010

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001882
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS ICMP Path MTU lowered below acceptable threshold"; itype: 3; icode: 4; byte_test:2,<,576,6; byte_test:2,!=,0,7; reference:cve,CAN-2004-1060; reference:url,www.microsoft.com/technet/security/bulletin/MS05-019.mspx; reference:url,isc.sans.org/diary.php?date=2005-04-12; reference:url,doc.emergingthreats.net/bin/view/Main/2001882; classtype:denial-of-service; sid:2001882; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICMP Path MTU lowered below acceptable threshold** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : cve,CAN-2004-1060|url,www.microsoft.com/technet/security/bulletin/MS05-019.mspx|url,isc.sans.org/diary.php?date=2005-04-12|url,doc.emergingthreats.net/bin/view/Main/2001882

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001366
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"ET DOS Possible Microsoft SQL Server Remote Denial Of Service Attempt"; flow: established,to_server; content:"|10 00 00 10 cc|"; depth:5; reference:bugtraq,11265; reference:url,doc.emergingthreats.net/bin/view/Main/2001366; classtype:attempted-dos; sid:2001366; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Microsoft SQL Server Remote Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,11265|url,doc.emergingthreats.net/bin/view/Main/2001366

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003236
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET DOS NetrWkstaUserEnum Request with large Preferred Max Len"; flow:established,to_server; content:"|ff|SMB"; content:"|10 00 00 00|"; distance:0; content:"|02 00|"; distance:14; within:2; byte_jump:4,12,relative,little,multiplier 2; content:"|00 00 00 00 00 00 00 00|"; distance:12; within:8; byte_test:4,>,2,0,relative; reference:cve,2006-6723; reference:url,doc.emergingthreats.net/bin/view/Main/2003236; classtype:attempted-dos; sid:2003236; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NetrWkstaUserEnum Request with large Preferred Max Len** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2006-6723|url,doc.emergingthreats.net/bin/view/Main/2003236

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012938
`#alert http $EXTERNAL_NET any -> $HOME_NET 9495 (msg:"ET DOS IBM Tivoli Endpoint Buffer Overflow Attempt"; flow:established,to_server; content:"POST"; http_method; isdataat:261; content:!"|0A|"; depth:261; reference:url, zerodayinitiative.com/advisories/ZDI-11-169/; classtype:denial-of-service; sid:2012938; rev:2; metadata:created_at 2011_06_07, updated_at 2011_06_07;)
` 

Name : **IBM Tivoli Endpoint Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url, zerodayinitiative.com/advisories/ZDI-11-169/

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2011-06-07

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000006
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Cisco Router HTTP DoS"; flow:to_server,established; content:"/%%"; http_uri; reference:url,www.cisco.com/warp/public/707/cisco-sn-20040326-exploits.shtml; classtype:attempted-dos; sid:2000006; rev:13; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Router HTTP DoS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.cisco.com/warp/public/707/cisco-sn-20040326-exploits.shtml

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 13

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010554
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Netgear DG632 Web Management Denial Of Service Attempt"; flow:established,to_server; content:"POST"; http_method; content:"/cgi-bin/firmwarecfg"; http_uri; nocase; reference:url, securitytracker.com/alerts/2009/Jun/1022403.html; reference:cve,2009-2256; reference:url,doc.emergingthreats.net/2010554; classtype:attempted-dos; sid:2010554; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Netgear DG632 Web Management Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url, securitytracker.com/alerts/2009/Jun/1022403.html|cve,2009-2256|url,doc.emergingthreats.net/2010554

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014386
`#alert tcp any any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop (RDP) Session Established Flowbit Set"; flow:to_server,established; flowbits:isset,ms.rdp.synack; flowbits:unset,ms.rdp.synack; flowbits:set,ms.rdp.established; flowbits:noalert; metadata: former_category DOS; reference:cve,2012-0152; classtype:not-suspicious; sid:2014386; rev:2; metadata:created_at 2012_03_15, updated_at 2012_03_15;)
` 

Name : **Microsoft Remote Desktop (RDP) Session Established Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : cve,2012-0152

CVE reference : Not defined

Creation date : 2012-03-15

Last modified date : 2012-03-15

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014384
`#alert tcp any any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt"; flags:R; flow:to_server; flowbits:isset,ms.rdp.synack; flowbits:isnotset,ms.rdp.established; flowbits:unset,ms.rdp.synack; reference:cve,2012-0152; classtype:attempted-dos; sid:2014384; rev:8; metadata:created_at 2012_03_13, updated_at 2012_03_13;)
` 

Name : **Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2012-0152

CVE reference : Not defined

Creation date : 2012-03-13

Last modified date : 2012-03-13

Rev version : 8

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010674
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Cisco 4200 Wireless Lan Controller Long Authorisation Denial of Service Attempt"; flow:to_server,established; content:"GET"; http_method; nocase; content:"/screens/frameset.html"; fast_pattern; http_uri; nocase; content:"Authorization|3A 20|Basic"; nocase; content:!"|0a|"; distance:2; within:118; isdataat:120,relative; pcre:"/^Authorization\x3A Basic.{120}/Hmi"; reference:url,www.securityfocus.com/bid/35805; reference:url,www.cisco.com/warp/public/707/cisco-amb-20090727-wlc.shtml; reference:cve,2009-1164; reference:url,doc.emergingthreats.net/2010674; classtype:attempted-dos; sid:2010674; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco 4200 Wireless Lan Controller Long Authorisation Denial of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.securityfocus.com/bid/35805|url,www.cisco.com/warp/public/707/cisco-amb-20090727-wlc.shtml|cve,2009-1164|url,doc.emergingthreats.net/2010674

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014662
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Integer indef DoS Attempt"; flow:to_server,established; content:"|03 00|"; depth:2; content:"|e0|"; distance:3; within:1; content:"|03 00|"; distance:0; content:"|f0|"; distance:3; within:1; content:"|7f 65|"; distance:1; within:2; content:"|04 01 01 04 01 01 01 01 ff 30|"; distance:3; within:10; content:"|02|"; distance:1; within:1; byte_test:1,>,0x80,0,relative; byte_test:1,<,0xFF,0,relative; byte_jump:1,0,relative, post_offset -128; byte_jump:1,-1,relative; byte_test:1,<,0x06,-1,relative,big; reference:url,www.msdn.microsoft.com/en-us/library/cc240836.aspx; reference:cve,2012-0002; reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-020; reference:url,stratsec.blogspot.com.au/2012/03/ms12-020 vulnerability-for-breakfast.html; reference:url,aluigi.org/adv/termdd_1-adv.txt; reference:url,blog.binaryninjas.org/?p=58; reference:url,luca.ntop.org/Teaching/Appunti/asn1.html; classtype:attempted-dos; sid:2014662; rev:1; metadata:created_at 2012_05_02, updated_at 2012_05_02;)
` 

Name : **Microsoft Remote Desktop Protocol (RDP) maxChannelIds Integer indef DoS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.msdn.microsoft.com/en-us/library/cc240836.aspx|cve,2012-0002|url,technet.microsoft.com/en-us/security/bulletin/ms12-020|url,stratsec.blogspot.com.au/2012/03/ms12-020 vulnerability-for-breakfast.html|url,aluigi.org/adv/termdd_1-adv.txt|url,blog.binaryninjas.org/?p=58|url,luca.ntop.org/Teaching/Appunti/asn1.html

CVE reference : Not defined

Creation date : 2012-05-02

Last modified date : 2012-05-02

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014663
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Negative Integer indef DoS Attempt"; flow:to_server,established; content:"|03 00|"; depth:2; content:"|e0|"; distance:3; within:1; content:"|03 00|"; distance:0; content:"|f0|"; distance:3; within:1; content:"|7f 65|"; distance:1; within:2; content:"|04 01 01 04 01 01 01 01 ff 30|"; distance:3; within:10; content:"|02|"; distance:1; within:1; byte_test:1,>,0x80,0,relative; byte_test:1,<,0xFF,0,relative; byte_jump:1,0,relative, post_offset -128; byte_jump:1,-1,relative; byte_test:1,&,0x80,-1,relative,big; reference:url, www.msdn.microsoft.com/en-us/library/cc240836.aspx; reference:cve,2012-0002; reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-020; reference:url,stratsec.blogspot.com.au/2012/03/ms12-020 vulnerability-for-breakfast.html; reference:url,aluigi.org/adv/termdd_1-adv.txt; reference:url,blog.binaryninjas.org/?p=58; reference:url,luca.ntop.org/Teaching/Appunti/asn1.html; classtype:attempted-dos; sid:2014663; rev:1; metadata:created_at 2012_05_02, updated_at 2012_05_02;)
` 

Name : **Microsoft Remote Desktop Protocol (RDP) maxChannelIds Negative Integer indef DoS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url, www.msdn.microsoft.com/en-us/library/cc240836.aspx|cve,2012-0002|url,technet.microsoft.com/en-us/security/bulletin/ms12-020|url,stratsec.blogspot.com.au/2012/03/ms12-020 vulnerability-for-breakfast.html|url,aluigi.org/adv/termdd_1-adv.txt|url,blog.binaryninjas.org/?p=58|url,luca.ntop.org/Teaching/Appunti/asn1.html

CVE reference : Not defined

Creation date : 2012-05-02

Last modified date : 2012-05-02

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014430
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds DoS Attempt Negative INT"; flow:to_server,established; content:"|03 00|"; depth:2; content:"|e0|"; distance:3; within:1; content:"|03 00|"; distance:0; content:"|f0|"; distance:3; within:1; content:"|7f 65|"; distance:1; within:2; content:"|04 01 01 04 01 01 01 01 ff 30|"; distance:3; within:10; content:"|02|"; distance:1; within:1; byte_test:1,<,0x80,0,relative,big; byte_test:1,&,0x80,1,relative,big; reference:url,www.msdn.microsoft.com/en-us/library/cc240836.aspx; reference:cve,2012-0002; reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-020; reference:url,stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html; reference:url,aluigi.org/adv/termdd_1-adv.txt; reference:url,blog.binaryninjas.org/?p=58; reference:url,luca.ntop.org/Teaching/Appunti/asn1.html; classtype:attempted-dos; sid:2014430; rev:13; metadata:created_at 2012_03_20, updated_at 2012_03_20;)
` 

Name : **Microsoft Remote Desktop Protocol (RDP) maxChannelIds DoS Attempt Negative INT** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.msdn.microsoft.com/en-us/library/cc240836.aspx|cve,2012-0002|url,technet.microsoft.com/en-us/security/bulletin/ms12-020|url,stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html|url,aluigi.org/adv/termdd_1-adv.txt|url,blog.binaryninjas.org/?p=58|url,luca.ntop.org/Teaching/Appunti/asn1.html

CVE reference : Not defined

Creation date : 2012-03-20

Last modified date : 2012-03-20

Rev version : 13

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014996
`#alert icmp any any -> any any (msg:"ET DOS Microsoft Windows 7 ICMPv6 Router Advertisement Flood"; itype:134; icode:0; byte_test:1,&,0x08,2; content:"|03|"; offset:20; depth:1; byte_test:1,&,0x40,2,relative; byte_test:1,&,0x80,2,relative; threshold:type threshold, track by_src, count 10, seconds 1; reference:url,www.samsclass.info/ipv6/proj/proj8x-124-flood-router.htm; classtype:attempted-dos; sid:2014996; rev:3; metadata:created_at 2012_07_02, updated_at 2012_07_02;)
` 

Name : **Microsoft Windows 7 ICMPv6 Router Advertisement Flood** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.samsclass.info/ipv6/proj/proj8x-124-flood-router.htm

CVE reference : Not defined

Creation date : 2012-07-02

Last modified date : 2012-07-02

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100272
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL DOS IGMP dos attack"; fragbits:M+; ip_proto:2; reference:bugtraq,514; reference:cve,1999-0918; reference:url,www.microsoft.com/technet/security/bulletin/MS99-034.mspx; classtype:attempted-dos; sid:2100272; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IGMP dos attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,514|cve,1999-0918|url,www.microsoft.com/technet/security/bulletin/MS99-034.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : DOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100268
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL DOS Jolt attack"; dsize:408; fragbits:M; reference:cve,1999-0345; classtype:attempted-dos; sid:2100268; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jolt attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,1999-0345

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014431
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds DoS Attempt"; flow:to_server,established; content:"|03 00|"; depth:2; content:"|e0|"; distance:3; within:1; content:"|03 00|"; distance:0; content:"|f0|"; distance:3; within:1; content:"|7f 65|"; distance:1; within:2; content:"|04 01 01 04 01 01 01 01 ff 30|"; distance:3; within:10; content:"|02|"; distance:1; within:1; byte_test:1,<,0x80,0,relative,big; byte_jump:1,0,relative; byte_test:1,<,0x06,-1,relative,big; reference:url,www.msdn.microsoft.com/en-us/library/cc240836.aspx; reference:cve,2012-0002; reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-020; reference:url,stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html; reference:url,aluigi.org/adv/termdd_1-adv.txt; reference:url,blog.binaryninjas.org/?p=58; reference:url,luca.ntop.org/Teaching/Appunti/asn1.html; classtype:attempted-dos; sid:2014431; rev:15; metadata:created_at 2012_03_20, updated_at 2012_03_20;)
` 

Name : **Microsoft Remote Desktop Protocol (RDP) maxChannelIds DoS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.msdn.microsoft.com/en-us/library/cc240836.aspx|cve,2012-0002|url,technet.microsoft.com/en-us/security/bulletin/ms12-020|url,stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html|url,aluigi.org/adv/termdd_1-adv.txt|url,blog.binaryninjas.org/?p=58|url,luca.ntop.org/Teaching/Appunti/asn1.html

CVE reference : Not defined

Creation date : 2012-03-20

Last modified date : 2012-03-20

Rev version : 15

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014385
`alert tcp $HOME_NET 3389 -> any any (msg:"ET DOS Microsoft Remote Desktop (RDP) Syn/Ack Outbound Flowbit Set"; flow:from_server; flags:SA; flowbits:isnotset,ms.rdp.synack; flowbits:set,ms.rdp.synack; flowbits:noalert; reference:cve,2012-0152; classtype:not-suspicious; sid:2014385; rev:5; metadata:created_at 2012_03_15, updated_at 2012_03_15;)
` 

Name : **Microsoft Remote Desktop (RDP) Syn/Ack Outbound Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : cve,2012-0152

CVE reference : Not defined

Creation date : 2012-03-15

Last modified date : 2012-03-15

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016323
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET DOS LibuPnP CVE-2012-5963 ST UDN Buffer Overflow"; content:"|0D 0A|ST|3A|"; nocase; pcre:"/^[^\r\n]*uuid\x3a[^\r\n\x3a]{181}/Ri"; reference:cve,CVE-2012-5963; classtype:attempted-dos; sid:2016323; rev:1; metadata:created_at 2013_01_31, updated_at 2013_01_31;)
` 

Name : **LibuPnP CVE-2012-5963 ST UDN Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,CVE-2012-5963

CVE reference : Not defined

Creation date : 2013-01-31

Last modified date : 2013-01-31

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016364
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS CVE-2013-0230 Miniupnpd SoapAction MethodName Buffer Overflow"; flow:to_server,established; content:"POST "; depth:5; content:"|0d 0a|SOAPAction|3a|"; nocase; distance:0; pcre:"/^[^\r\n]+#[^\x22\r\n]{2049}/R"; reference:url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play; reference:url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf; reference:cve,CVE-2013-0230; classtype:attempted-dos; sid:2016364; rev:1; metadata:created_at 2013_02_06, updated_at 2013_02_06;)
` 

Name : **CVE-2013-0230 Miniupnpd SoapAction MethodName Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play|url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf|cve,CVE-2013-0230

CVE reference : Not defined

Creation date : 2013-02-06

Last modified date : 2013-02-06

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016363
`alert udp any any -> $HOME_NET 1900 (msg:"ET DOS Miniupnpd M-SEARCH Buffer Overflow CVE-2013-0229"; content:"M-SEARCH"; depth:8; isdataat:1492,relative; content:!"|0d 0a|"; distance:1490; within:2; reference:url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play; reference:url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf; reference:cve,CVE-2013-0229; classtype:attempted-dos; sid:2016363; rev:2; metadata:created_at 2013_02_06, updated_at 2013_02_06;)
` 

Name : **Miniupnpd M-SEARCH Buffer Overflow CVE-2013-0229** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play|url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf|cve,CVE-2013-0229

CVE reference : Not defined

Creation date : 2013-02-06

Last modified date : 2013-02-06

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002853
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 2049 (msg:"ET DOS FreeBSD NFS RPC Kernel Panic"; flow:to_server,established; content:"|00 01 86 a5|"; offset:16; depth:4; content:"|00 00 00 01|"; distance:4; within:4; content:"|00 00 00 00|"; offset:8; depth:4; content:"|00 00 00 00 00 00|"; offset:0; depth:6; reference:cve,2006-0900; reference:bugtraq,19017; reference:url,doc.emergingthreats.net/bin/view/Main/2002853; classtype:attempted-dos; sid:2002853; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FreeBSD NFS RPC Kernel Panic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2006-0900|bugtraq,19017|url,doc.emergingthreats.net/bin/view/Main/2002853

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017154
`#alert http any any -> $HOME_NET 3128 (msg:"ET DOS Squid-3.3.5 DoS"; flow:established,to_server; content:"Host|3a| "; http_header; pcre:"/^Host\x3a[^\x3a\r\n]+?\x3a[^\r\n]{6}/Hmi"; classtype:attempted-dos; sid:2017154; rev:2; metadata:created_at 2013_07_16, updated_at 2013_07_16;)
` 

Name : **Squid-3.3.5 DoS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-16

Last modified date : 2013-07-16

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017722
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS Trojan.BlackRev V1.Botnet HTTP Login POST Flood Traffic Inbound"; flow:established,to_server; content:"POST"; http_method; content:"Mozilla/4.0 (compatible|3B| Synapse)"; fast_pattern:24,9; http_user_agent; content:"login="; http_client_body; depth:6; content:"$pass="; http_client_body; within:50; threshold: type both, count 5, seconds 60, track by_src; reference:url,www.btpro.net/blog/2013/05/black-revolution-botnet-trojan/; classtype:attempted-dos; sid:2017722; rev:3; metadata:created_at 2013_11_14, updated_at 2013_11_14;)
` 

Name : **Trojan.BlackRev V1.Botnet HTTP Login POST Flood Traffic Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.btpro.net/blog/2013/05/black-revolution-botnet-trojan/

CVE reference : Not defined

Creation date : 2013-11-14

Last modified date : 2013-11-14

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017918
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x02"; content:"|00 02 2A|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; classtype:attempted-dos; sid:2017918; rev:2; metadata:created_at 2014_01_02, updated_at 2014_01_02;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks

CVE reference : Not defined

Creation date : 2014-01-02

Last modified date : 2014-01-02

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017919
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03"; content:"|00 03 2A|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; classtype:attempted-dos; sid:2017919; rev:2; metadata:created_at 2014_01_02, updated_at 2014_01_02;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks

CVE reference : Not defined

Creation date : 2014-01-02

Last modified date : 2014-01-02

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017920
`alert udp $HOME_NET 123 -> $EXTERNAL_NET any (msg:"ET DOS Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x02"; content:"|00 02 2a|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 2,seconds 60; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; classtype:attempted-dos; sid:2017920; rev:2; metadata:created_at 2014_01_02, updated_at 2014_01_02;)
` 

Name : **Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks

CVE reference : Not defined

Creation date : 2014-01-02

Last modified date : 2014-01-02

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017921
`alert udp $HOME_NET 123 -> $EXTERNAL_NET any (msg:"ET DOS Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x03"; content:"|00 03 2a|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 2,seconds 60; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; classtype:attempted-dos; sid:2017921; rev:2; metadata:created_at 2014_01_02, updated_at 2014_01_02;)
` 

Name : **Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks

CVE reference : Not defined

Creation date : 2014-01-02

Last modified date : 2014-01-02

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017965
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x02"; content:"|00 02 2a|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2017965; rev:3; metadata:created_at 2014_01_13, updated_at 2014_01_13;)
` 

Name : **Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-01-13

Last modified date : 2014-01-13

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018208
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS Inbound GoldenEye DoS attack"; flow:established,to_server; content:"/?"; fast_pattern; http_uri; depth:2; content:"="; http_uri; distance:3; within:11; pcre:"/^\/\?[a-zA-Z0-9]{3,10}=[a-zA-Z0-9]{3,20}(?:&[a-zA-Z0-9]{3,10}=[a-zA-Z0-9]{3,20})*?$/U"; content:"Keep|2d|Alive|3a|"; http_header; content:"Connection|3a| keep|2d|alive"; http_header; content:"Cache|2d|Control|3a|"; http_header; pcre:"/^Cache-Control\x3a\x20(?:max-age=0|no-cache)\r?$/Hm"; content:"Accept|2d|Encoding|3a|"; http_header; threshold: type both, track by_src, count 100, seconds 300; reference:url,github.com/jseidl/GoldenEye; classtype:denial-of-service; sid:2018208; rev:2; metadata:created_at 2014_03_04, updated_at 2014_03_04;)
` 

Name : **Inbound GoldenEye DoS attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,github.com/jseidl/GoldenEye

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2014-03-04

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019010
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x02"; content:"|00 02 00|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019010; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019011
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x03"; content:"|00 03 00|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019011; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019012
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x02"; content:"|00 02 01|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019012; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019013
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x03"; content:"|00 03 01|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019013; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019102
`alert udp any any -> $HOME_NET 1900 (msg:"ET DOS Possible SSDP Amplification Scan in Progress"; content:"M-SEARCH * HTTP/1.1"; content:"ST|3a 20|ssdp|3a|all|0d 0a|"; nocase; distance:0; fast_pattern; threshold: type both,track by_src,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/29/weekly-metasploit-update; classtype:attempted-dos; sid:2019102; rev:1; metadata:created_at 2014_09_02, updated_at 2014_09_02;)
` 

Name : **Possible SSDP Amplification Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/29/weekly-metasploit-update

CVE reference : Not defined

Creation date : 2014-09-02

Last modified date : 2014-09-02

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009414
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Large amount of TCP ZeroWindow - Possible Nkiller2 DDos attack"; flags:A; window:0; threshold: type both, track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2009414; classtype:attempted-dos; sid:2009414; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Large amount of TCP ZeroWindow - Possible Nkiller2 DDos attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2009414

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012048
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS"; flow:to_server,established; content:"hihihihihihihihihihihihihihihihi"; nocase; threshold: type limit,track by_src,seconds 180,count 1; reference:url,www.isc.sans.org/diary.html?storyid=10051; classtype:trojan-activity; sid:2012048; rev:5; metadata:created_at 2010_12_13, updated_at 2010_12_13;)
` 

Name : **Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.isc.sans.org/diary.html?storyid=10051

CVE reference : Not defined

Creation date : 2010-12-13

Last modified date : 2010-12-13

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012049
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu string"; flow:to_server,established; content:"desudesudesu"; nocase; threshold: type limit,track by_src,seconds 180,count 1; reference:url,www.isc.sans.org/diary.html?storyid=10051; classtype:trojan-activity; sid:2012049; rev:5; metadata:created_at 2010_12_13, updated_at 2010_12_13;)
` 

Name : **Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu string** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.isc.sans.org/diary.html?storyid=10051

CVE reference : Not defined

Creation date : 2010-12-13

Last modified date : 2010-12-13

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012050
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS desu string"; flow:to_server,established; content:"desudesudesu"; nocase; threshold: type limit,track by_src,seconds 180,count 1; reference:url,www.isc.sans.org/diary.html?storyid=10051; classtype:trojan-activity; sid:2012050; rev:5; metadata:created_at 2010_12_13, updated_at 2010_12_13;)
` 

Name : **Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS desu string** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.isc.sans.org/diary.html?storyid=10051

CVE reference : Not defined

Creation date : 2010-12-13

Last modified date : 2010-12-13

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014141
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS LOIC Javascript DDoS Outbound"; flow:established,to_server; content:"GET"; http_method; content:"/?id="; fast_pattern; http_uri; depth:5; content:"&msg="; http_uri; distance:13; within:5; pcre:"/^\/\?id=[0-9]{13}&msg=/U"; threshold: type both, track by_src, count 5, seconds 60; reference:url,isc.sans.org/diary/Javascript+DDoS+Tool+Analysis/12442; reference:url,www.wired.com/threatlevel/2012/01/anons-rickroll-botnet; classtype:attempted-dos; sid:2014141; rev:5; metadata:created_at 2012_01_23, updated_at 2012_01_23;)
` 

Name : **LOIC Javascript DDoS Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,isc.sans.org/diary/Javascript+DDoS+Tool+Analysis/12442|url,www.wired.com/threatlevel/2012/01/anons-rickroll-botnet

CVE reference : Not defined

Creation date : 2012-01-23

Last modified date : 2012-01-23

Rev version : 5

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016030
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS LOIC POST"; flow:established,to_server; content:"POST"; http_method; content:"13"; depth:2; http_client_body; content:"=MSG"; fast_pattern; http_client_body; distance:11; within:4; pcre:"/^13\d{11}/P"; threshold:type limit, track by_src, count 1, seconds 300; classtype:web-application-attack; sid:2016030; rev:4; metadata:created_at 2012_12_13, updated_at 2012_12_13;)
` 

Name : **LOIC POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-13

Last modified date : 2012-12-13

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016031
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS LOIC GET"; flow:established,to_server; content:"GET"; http_method; content:"/?msg=MSG"; http_uri; threshold:type limit, track by_src, count 1, seconds 300; classtype:web-application-attack; sid:2016031; rev:3; metadata:created_at 2012_12_13, updated_at 2012_12_13;)
` 

Name : **LOIC GET** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-13

Last modified date : 2012-12-13

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011821
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS User-Agent used in known DDoS Attacks Detected outbound"; flow:established,to_server; content:"User-agent|3a| Mozilla/5.0 (Windows|3b| U|3b| Windows NT 5.1|3b| ru|3b| rv|3a|1.8.1.1) Gecko/20061204 Firefox/2.0.0.1"; http_header; reference:url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/; classtype:denial-of-service; sid:2011821; rev:3; metadata:created_at 2010_10_18, updated_at 2010_10_18;)
` 

Name : **User-Agent used in known DDoS Attacks Detected outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/

CVE reference : Not defined

Creation date : 2010-10-18

Last modified date : 2010-10-18

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011822
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS User-Agent used in known DDoS Attacks Detected inbound"; flow:established,to_server; content:"User-agent|3a| Mozilla/5.0 (Windows|3b| U|3b| Windows NT 5.1|3b| ru|3b| rv|3a|1.8.1.1) Gecko/20061204 Firefox/2.0.0.1"; http_header; reference:url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/; classtype:denial-of-service; sid:2011822; rev:3; metadata:created_at 2010_10_18, updated_at 2010_10_18;)
` 

Name : **User-Agent used in known DDoS Attacks Detected inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/

CVE reference : Not defined

Creation date : 2010-10-18

Last modified date : 2010-10-18

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011823
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS User-Agent used in known DDoS Attacks Detected outbound 2"; flow:established,to_server; content:"User-agent|3a| Opera/9.02 (Windows NT 5.1|3b| U|3b| ru)"; http_header; reference:url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/; classtype:denial-of-service; sid:2011823; rev:3; metadata:created_at 2010_10_18, updated_at 2010_10_18;)
` 

Name : **User-Agent used in known DDoS Attacks Detected outbound 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/

CVE reference : Not defined

Creation date : 2010-10-18

Last modified date : 2010-10-18

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011824
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS User-Agent used in known DDoS Attacks Detected inbound 2"; flow:established,to_server; content:"User-agent|3a| Opera/9.02 (Windows NT 5.1|3b| U|3b| ru)"; http_header; reference:url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/; classtype:denial-of-service; sid:2011824; rev:4; metadata:created_at 2010_10_18, updated_at 2010_10_18;)
` 

Name : **User-Agent used in known DDoS Attacks Detected inbound 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,www.linuxquestions.org/questions/linux-security-4/massive-ddos-need-advice-help-795298/

CVE reference : Not defined

Creation date : 2010-10-18

Last modified date : 2010-10-18

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010624
`#alert tcp $EXTERNAL_NET any -> $HOME_NET [22,23,80,443,10000] (msg:"ET DOS Possible Cisco PIX/ASA Denial Of Service Attempt (Hping Created Packets)"; flow:to_server; content:"|58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58|"; depth:40; content:"|58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58|"; distance:300; isdataat:300,relative; threshold: type threshold, track by_src, count 60, seconds 80; reference:url,www.securityfocus.com/bid/34429/info; reference:url,www.securityfocus.com/bid/34429/exploit; reference:url,www.cisco.com/en/US/products/products_applied_mitigation_bulletin09186a0080a99518.html; reference:cve,2009-1157; reference:url,doc.emergingthreats.net/2010624; classtype:attempted-dos; sid:2010624; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Cisco PIX/ASA Denial Of Service Attempt (Hping Created Packets)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.securityfocus.com/bid/34429/info|url,www.securityfocus.com/bid/34429/exploit|url,www.cisco.com/en/US/products/products_applied_mitigation_bulletin09186a0080a99518.html|cve,2009-1157|url,doc.emergingthreats.net/2010624

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016017
`#alert udp $HOME_NET 53 -> any any (msg:"ET DOS DNS Amplification Attack Outbound"; content:"|01 00 00 01 00 00 00 00 00 01|"; depth:10; offset:2; pcre:"/^[^\x00]+?\x00/R"; content:"|00 ff 00 01 00 00 29|"; within:7; fast_pattern; byte_test:2,>,4095,0,relative; threshold: type limit, track by_src, seconds 60, count 1; classtype:bad-unknown; sid:2016017; rev:7; metadata:created_at 2012_12_11, updated_at 2012_12_11;)
` 

Name : **DNS Amplification Attack Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-11

Last modified date : 2012-12-11

Rev version : 7

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016016
`alert udp any any -> $HOME_NET 53 (msg:"ET DOS DNS Amplification Attack Inbound"; content:"|01 00 00 01 00 00 00 00 00 01|"; depth:10; offset:2; pcre:"/^[^\x00]+?\x00/R"; content:"|00 ff 00 01 00 00 29|"; within:7; fast_pattern; byte_test:2,>,4095,0,relative; threshold: type both, track by_dst, seconds 60, count 5; classtype:bad-unknown; sid:2016016; rev:8; metadata:created_at 2012_12_11, updated_at 2012_12_11;)
` 

Name : **DNS Amplification Attack Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-11

Last modified date : 2012-12-11

Rev version : 8

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017966
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x03"; content:"|00 03 2a|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2017966; rev:3; metadata:created_at 2014_01_13, updated_at 2014_01_13;)
` 

Name : **Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.symantec.com/connect/blogs/hackers-spend-christmas-break-launching-large-scale-ntp-reflection-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-01-13

Last modified date : 2014-01-13

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019350
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Terse HTTP GET Likely GoodBye 5.2 DDoS tool"; flow:to_server,established; dsize:<50; content:"|20|HTTP/1.1Host|3a 20|"; threshold:type both,track by_dst,count 500,seconds 60; classtype:attempted-dos; sid:2019350; rev:2; metadata:created_at 2014_10_03, updated_at 2014_10_03;)
` 

Name : **Terse HTTP GET Likely GoodBye 5.2 DDoS tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-03

Last modified date : 2014-10-03

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019346
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Terse HTTP GET Likely LOIC"; flow:to_server,established; dsize:18; content:"GET / HTTP/1.1|0d 0a 0d 0a|"; depth:18; threshold:type both,track by_dst,count 500,seconds 60; classtype:attempted-dos; sid:2019346; rev:2; metadata:created_at 2014_10_03, updated_at 2014_10_03;)
` 

Name : **Terse HTTP GET Likely LOIC** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-03

Last modified date : 2014-10-03

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019347
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS HTTP GET AAAAAAAA Likely FireFlood"; flow:to_server,established; content:"GET AAAAAAAA HTTP/1.1"; content:!"Referer|3a|"; distance:0; content:!"Accept"; distance:0; content:!"|0d 0a|"; distance:0; threshold:type both,track by_dst,count 500,seconds 60; classtype:attempted-dos; sid:2019347; rev:2; metadata:created_at 2014_10_03, updated_at 2014_10_03;)
` 

Name : **HTTP GET AAAAAAAA Likely FireFlood** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-03

Last modified date : 2014-10-03

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019348
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Terse HTTP GET Likely AnonMafiaIC DDoS tool"; flow:to_server,established; dsize:20; content:"GET / HTTP/1.0|0d 0a 0d 0a 0d 0a|"; depth:20; threshold:type both,track by_dst,count 500,seconds 60; classtype:attempted-dos; sid:2019348; rev:2; metadata:created_at 2014_10_03, updated_at 2014_10_03;)
` 

Name : **Terse HTTP GET Likely AnonMafiaIC DDoS tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-03

Last modified date : 2014-10-03

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019349
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET DOS Terse HTTP GET Likely AnonGhost DDoS tool"; flow:to_server,established; dsize:20; content:"GET / HTTP/1.1|0d 0a 0d 0a 0d 0a|"; depth:20; threshold:type both,track by_dst,count 500,seconds 60; classtype:attempted-dos; sid:2019349; rev:2; metadata:created_at 2014_10_03, updated_at 2014_10_03;)
` 

Name : **Terse HTTP GET Likely AnonGhost DDoS tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-03

Last modified date : 2014-10-03

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019014
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress GET_RESTRICT Response to Non-Ephemeral Port IMPL 0x03"; content:"|00 03 10|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019014; rev:4; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress GET_RESTRICT Response to Non-Ephemeral Port IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019015
`alert udp any 123 -> any 0:1023 (msg:"ET DOS Likely NTP DDoS In Progress GET_RESTRICT Response to Non-Ephemeral Port IMPL 0x02"; content:"|00 02 10|"; offset:1; depth:3; byte_test:1,&,128,0; byte_test:1,&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_src,count 1,seconds 120; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; reference:url,en.wikipedia.org/wiki/Ephemeral_port; classtype:attempted-dos; sid:2019015; rev:4; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress GET_RESTRICT Response to Non-Ephemeral Port IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks|url,en.wikipedia.org/wiki/Ephemeral_port

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019016
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST Requests IMPL 0x03"; content:"|00 03 00|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019016; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST Requests IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019017
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST Requests IMPL 0x02"; content:"|00 02 00|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019017; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST Requests IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019018
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST_SUM Requests IMPL 0x03"; content:"|00 03 01|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019018; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST_SUM Requests IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019019
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST_SUM Requests IMPL 0x02"; content:"|00 02 01|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019019; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed PEER_LIST_SUM Requests IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019021
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed GET_RESTRICT Requests IMPL 0x02"; content:"|00 02 10|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019021; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed GET_RESTRICT Requests IMPL 0x02** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019020
`alert udp any any -> any 123 (msg:"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed GET_RESTRICT Requests IMPL 0x03"; content:"|00 03 10|"; offset:1; depth:3; byte_test:1,!&,128,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,&,1,0; threshold: type both,track by_dst,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019020; rev:3; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Possible NTP DDoS Inbound Frequent Un-Authed GET_RESTRICT Requests IMPL 0x03** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019022
`alert udp any 123 -> any any (msg:"ET DOS Likely NTP DDoS In Progress Multiple UNSETTRAP Mode 6 Responses"; content:"|df 00 00 04 00|"; offset:1; depth:5; byte_test:1,!&,128,0; byte_test:1,!&,64,0; byte_test:1,&,4,0; byte_test:1,&,2,0; byte_test:1,!&,1,0; threshold: type both,track by_src,count 2,seconds 60; reference:url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks; classtype:attempted-dos; sid:2019022; rev:4; metadata:created_at 2014_08_25, updated_at 2014_08_25;)
` 

Name : **Likely NTP DDoS In Progress Multiple UNSETTRAP Mode 6 Responses** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,community.rapid7.com/community/metasploit/blog/2014/08/25/r7-2014-12-more-amplification-vulnerabilities-in-ntp-allow-even-more-drdos-attacks

CVE reference : Not defined

Creation date : 2014-08-25

Last modified date : 2014-08-25

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018277
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS Possible WordPress Pingback DDoS in Progress (Inbound)"; flow:established,to_server; content:"/xmlrpc.php"; http_uri; nocase; content:"pingback.ping"; nocase; http_client_body; fast_pattern; threshold:type both, track  by_src, count 5, seconds 90; classtype:attempted-dos; sid:2018277; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2014_03_14, updated_at 2016_07_01;)
` 

Name : **Possible WordPress Pingback DDoS in Progress (Inbound)** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-14

Last modified date : 2016-07-01

Rev version : 3

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020305
`alert udp $HOME_NET 1434 -> $EXTERNAL_NET any (msg:"ET DOS MC-SQLR Response Outbound Possible DDoS Participation"; content:"|05|"; depth:1; content:"ServerName|3b|"; nocase; content:"InstanceName|3b|"; distance:0; content:"IsClustered|3b|"; distance:0; content:"Version|3b|"; distance:0; threshold:type both,track by_src,count 30,seconds 60; reference:url,kurtaubuchon.blogspot.com.es/2015/01/mc-sqlr-amplification-ms-sql-server.html; classtype:attempted-dos; sid:2020305; rev:4; metadata:created_at 2015_01_23, updated_at 2015_01_23;)
` 

Name : **MC-SQLR Response Outbound Possible DDoS Participation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,kurtaubuchon.blogspot.com.es/2015/01/mc-sqlr-amplification-ms-sql-server.html

CVE reference : Not defined

Creation date : 2015-01-23

Last modified date : 2015-01-23

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020306
`alert udp $EXTERNAL_NET 1434 -> $HOME_NET any (msg:"ET DOS MC-SQLR Response Inbound Possible DDoS Target"; content:"|05|"; depth:1; content:"ServerName|3b|"; nocase; content:"InstanceName|3b|"; distance:0; content:"IsClustered|3b|"; distance:0; content:"Version|3b|"; distance:0; threshold:type both,track by_dst,count 30,seconds 60; reference:url,kurtaubuchon.blogspot.com.es/2015/01/mc-sqlr-amplification-ms-sql-server.html; classtype:attempted-dos; sid:2020306; rev:3; metadata:created_at 2015_01_23, updated_at 2015_01_23;)
` 

Name : **MC-SQLR Response Inbound Possible DDoS Target** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,kurtaubuchon.blogspot.com.es/2015/01/mc-sqlr-amplification-ms-sql-server.html

CVE reference : Not defined

Creation date : 2015-01-23

Last modified date : 2015-01-23

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021170
`alert udp $HOME_NET 5093 -> $EXTERNAL_NET any (msg:"ET DOS Possible Sentinal LM  Application attack in progress Outbound (Response)"; dsize:>1390; content:"|7a 00 00 00 00 00 00 00 00 00 00 00|"; depth:12; threshold: type both,track by_src,count 10,seconds 60; classtype:attempted-dos; sid:2021170; rev:1; metadata:created_at 2015_05_29, updated_at 2015_05_29;)
` 

Name : **Possible Sentinal LM  Application attack in progress Outbound (Response)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-29

Last modified date : 2015-05-29

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021171
`alert udp $EXTERNAL_NET 5093 -> $HOME_NET any (msg:"ET DOS Possible Sentinal LM Amplification attack (Response) Inbound"; dsize:>1390; content:"|7a 00 00 00 00 00 00 00 00 00 00 00|"; depth:12; threshold: type both,track by_src,count 10,seconds 60; classtype:attempted-dos; sid:2021171; rev:1; metadata:created_at 2015_05_29, updated_at 2015_05_29;)
` 

Name : **Possible Sentinal LM Amplification attack (Response) Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-29

Last modified date : 2015-05-29

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021172
`alert udp $EXTERNAL_NET any -> $HOME_NET 5093 (msg:"ET DOS Possible Sentinal LM Amplification attack (Request) Inbound"; dsize:6; content:"|7a 00 00 00 00 00|"; threshold: type both,track by_dst,count 10,seconds 60; classtype:attempted-dos; sid:2021172; rev:1; metadata:created_at 2015_05_29, updated_at 2015_05_29;)
` 

Name : **Possible Sentinal LM Amplification attack (Request) Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-29

Last modified date : 2015-05-29

Rev version : 1

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013462
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Skype FindCountriesByNamePattern property Buffer Overflow Attempt"; flow:to_client,established; file_data; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"22C83263-E4B8-4233-82CD-FB047C6BF13E"; nocase; distance:0; content:".FindCountriesByNamePattern"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*22C83263-E4B8-4233-82CD-FB047C6BF13E/si"; reference:url,garage4hackers.com/f43/skype-5-x-activex-crash-poc-981.html; classtype:web-application-attack; sid:2013462; rev:3; metadata:created_at 2011_08_26, updated_at 2011_08_26;)
` 

Name : **Skype FindCountriesByNamePattern property Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,garage4hackers.com/f43/skype-5-x-activex-crash-poc-981.html

CVE reference : Not defined

Creation date : 2011-08-26

Last modified date : 2011-08-26

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013463
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Skype FindCountriesByNamePattern property Buffer Overflow Attempt Format String Function Call"; flow:to_client,established; file_data; content:"ActiveXObject"; nocase; content:"SkypePNRLib.PNR"; nocase; distance:0; content:".FindCountriesByNamePattern"; nocase; reference:url,garage4hackers.com/f43/skype-5-x-activex-crash-poc-981.html; classtype:attempted-user; sid:2013463; rev:3; metadata:created_at 2011_08_26, updated_at 2011_08_26;)
` 

Name : **Skype FindCountriesByNamePattern property Buffer Overflow Attempt Format String Function Call** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,garage4hackers.com/f43/skype-5-x-activex-crash-poc-981.html

CVE reference : Not defined

Creation date : 2011-08-26

Last modified date : 2011-08-26

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019404
`#alert tcp $EXTERNAL_NET 10000: -> $HOME_NET 0:1023 (msg:"ET DOS Potential Tsunami SYN Flood Denial Of Service Attempt"; flags:S; flow:to_server; dsize:>900; threshold: type both, count 20, seconds 120, track by_src; reference:url,security.radware.com/uploadedFiles/Resources_and_Content/Threat/TsunamiSYNFloodAttack.pdf; classtype:attempted-dos; sid:2019404; rev:3; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **Potential Tsunami SYN Flood Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,security.radware.com/uploadedFiles/Resources_and_Content/Threat/TsunamiSYNFloodAttack.pdf

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022760
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS Linux/Tsunami DOS User-Agent (x00_-gawa.sa.pilipinas.2015) INBOUND"; flow:to_server,established; content:"x00_-gawa.sa.pilipinas.2015"; http_user_agent; reference:url,vms.drweb.com/virus/?i=4656268; classtype:attempted-dos; sid:2022760; rev:2; metadata:created_at 2016_04_26, updated_at 2016_04_26;)
` 

Name : **Linux/Tsunami DOS User-Agent (x00_-gawa.sa.pilipinas.2015) INBOUND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,vms.drweb.com/virus/?i=4656268

CVE reference : Not defined

Creation date : 2016-04-26

Last modified date : 2016-04-26

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023054
`alert udp $HOME_NET 53 -> $EXTERNAL_NET 1:1023 (msg:"ET DOS DNS Amplification Attack Possible Outbound Windows Non-Recursive Root Hint Reserved Port"; content:"|81 00 00 01 00 00|"; depth:6; offset:2; byte_test:2,>,10,0,relative; byte_test:2,>,10,2,relative; content:"|0c|root-servers|03|net|00|"; distance:0; content:"|0c|root-servers|03|net|00|"; distance:0; threshold: type both, track by_dst, seconds 60, count 5; reference:url,twitter.com/sempersecurus/status/763749835421941760; reference:url,pastebin.com/LzubgtVb; classtype:bad-unknown; sid:2023054; rev:2; metadata:attack_target Server, deployment Datacenter, created_at 2016_08_12, performance_impact Low, updated_at 2016_08_12;)
` 

Name : **DNS Amplification Attack Possible Outbound Windows Non-Recursive Root Hint Reserved Port** 

Attack target : Server

Description : This signature will trip on possible DNS amplification attacks, due to the way that windows handles recursive lookups for non-existent domains. It will respond with roothints http://pastebin.com/LzubgtVb.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,twitter.com/sempersecurus/status/763749835421941760|url,pastebin.com/LzubgtVb

CVE reference : Not defined

Creation date : 2016-08-12

Last modified date : 2016-08-12

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023053
`alert udp $EXTERNAL_NET 53 -> $HOME_NET 1:1023 (msg:"ET DOS DNS Amplification Attack Possible Inbound Windows Non-Recursive Root Hint Reserved Port"; content:"|81 00 00 01 00 00|"; depth:6; offset:2; byte_test:2,>,10,0,relative; byte_test:2,>,10,2,relative; content:"|0c|root-servers|03|net|00|"; distance:0; content:"|0c|root-servers|03|net|00|"; distance:0; threshold: type both, track by_dst, seconds 60, count 5; reference:url,twitter.com/sempersecurus/status/763749835421941760; reference:url,pastebin.com/LzubgtVb; classtype:bad-unknown; sid:2023053; rev:2; metadata:attack_target Server, deployment Datacenter, created_at 2016_08_12, performance_impact Low, updated_at 2016_08_12;)
` 

Name : **DNS Amplification Attack Possible Inbound Windows Non-Recursive Root Hint Reserved Port** 

Attack target : Server

Description : This signature will trip on possible DNS amplification attacks, due to the way that windows handles recursive lookups for non-existent domains. It will respond with roothints http://pastebin.com/LzubgtVb.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,twitter.com/sempersecurus/status/763749835421941760|url,pastebin.com/LzubgtVb

CVE reference : Not defined

Creation date : 2016-08-12

Last modified date : 2016-08-12

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023831
`alert tcp any 445 -> $HOME_NET any (msg:"ET DOS Excessive Large Tree Connect Response"; flow:from_server,established; byte_test:  3,>,1000,1; content: "|fe 53 4d 42 40 00|"; offset: 4; depth: 6;  content: "|03 00|"; offset: 16; depth:2;  reference:url,isc.sans.edu/forums/diary/Windows+SMBv3+Denial+of+Service+Proof+of+Concept+0+Day+Exploit/22029/; classtype:attempted-dos; sid:2023831; rev:2; metadata:affected_product SMBv3, attack_target Client_and_Server, deployment Datacenter, signature_severity Major, created_at 2017_02_03, updated_at 2017_02_03;)
` 

Name : **Excessive Large Tree Connect Response** 

Attack target : Client_and_Server

Description : This signature matches an attempt to exploit Microsoft Windows SMB Tree Connect Response memory corruption vulnerability. Which causes a deny of service.

Tags : Not defined

Affected products : SMBv3

Alert Classtype : attempted-dos

URL reference : url,isc.sans.edu/forums/diary/Windows+SMBv3+Denial+of+Service+Proof+of+Concept+0+Day+Exploit/22029/

CVE reference : Not defined

Creation date : 2017-02-03

Last modified date : 2017-02-03

Rev version : 2

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023832
`alert tcp any 445 -> $HOME_NET any (msg:"ET DOS SMB Tree_Connect Stack Overflow Attempt (CVE-2017-0016)"; flow:from_server,established; content:"|FE|SMB"; offset:4; depth:4; content:"|03 00|"; distance:8; within:2; byte_test:1,&,1,2,relative; byte_jump:2,8,little,from_beginning; byte_jump:2,4,relative,little; isdataat:1000,relative; content:!"|FE|SMB"; within:1000; reference:cve,2017-0016; classtype:attempted-dos; sid:2023832; rev:3; metadata:affected_product SMBv3, attack_target Client_and_Server, deployment Datacenter, signature_severity Major, created_at 2017_02_03, updated_at 2017_02_07;)
` 

Name : **SMB Tree_Connect Stack Overflow Attempt (CVE-2017-0016)** 

Attack target : Client_and_Server

Description : This signature matches an attempt to exploit Microsoft Windows SMB Tree Connect Response memory corruption vulnerability. Which causes a deny of service.

Tags : Not defined

Affected products : SMBv3

Alert Classtype : attempted-dos

URL reference : cve,2017-0016

CVE reference : Not defined

Creation date : 2017-02-03

Last modified date : 2017-02-07

Rev version : 3

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023497
`alert tcp any any -> $HOME_NET 445 (msg:"ET DOS Microsoft Windows LSASS Remote Memory Corruption (CVE-2017-0004)"; flow:established,to_server; content:"|FF|SMB|73|"; offset:4; depth:5; byte_test:1,&,0x80,6,relative; byte_test:1,&,0x08,6,relative; byte_test:1,&,0x10,5,relative; byte_test:1,&,0x04,5,relative; byte_test:1,&,0x02,5,relative; byte_test:1,&,0x01,5,relative; content:"|ff 00|"; distance:28; within:2; content:"|84|"; distance:25; within:1; content:"NTLMSSP"; fast_pattern; within:64; reference:url,github.com/lgandx/PoC/tree/master/LSASS; reference:url,support.microsoft.com/en-us/kb/3216771; reference:url,support.microsoft.com/en-us/kb/3199173; reference:cve,2017-0004; reference:url,technet.microsoft.com/library/security/MS17-004; classtype:attempted-dos; sid:2023497; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, deployment Datacenter, signature_severity Major, created_at 2016_11_11, performance_impact Low, updated_at 2017_01_12;)
` 

Name : **Microsoft Windows LSASS Remote Memory Corruption (CVE-2017-0004)** 

Attack target : Client_and_Server

Description : This signature matches on a Malformed Packet SMB Session Setup AndX Request that can cause a Deny of Service on the target.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,github.com/lgandx/PoC/tree/master/LSASS|url,support.microsoft.com/en-us/kb/3216771|url,support.microsoft.com/en-us/kb/3199173|cve,2017-0004|url,technet.microsoft.com/library/security/MS17-004

CVE reference : Not defined

Creation date : 2016-11-11

Last modified date : 2017-01-12

Rev version : 3

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2024510
`#alert tcp any any -> $HOME_NET [139,445] (msg:"ET DOS Possible SMBLoris NBSS Length Mem Exhaustion Vuln Inbound"; flow:established,to_server; content:"|00 01|"; depth:2; threshold:type both,track by_dst,count 3, seconds 90; metadata: former_category DOS; reference:url,isc.sans.edu/forums/diary/SMBLoris+the+new+SMB+flaw/22662/; classtype:trojan-activity; sid:2024510; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Internal, signature_severity Major, created_at 2017_08_02, performance_impact Significant, updated_at 2017_08_02;)
` 

Name : **Possible SMBLoris NBSS Length Mem Exhaustion Vuln Inbound** 

Attack target : Client_and_Server

Description : Alerts on SMBloris DOS packet

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,isc.sans.edu/forums/diary/SMBLoris+the+new+SMB+flaw/22662/

CVE reference : Not defined

Creation date : 2017-08-02

Last modified date : 2017-08-02

Rev version : 1

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2024511
`alert tcp any any -> $HOME_NET [139,445] (msg:"ET DOS SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based)"; flow:established,to_server; content:"|00 01 ff ff|"; depth:4; threshold:type both,track by_dst,count 30, seconds 300; metadata: former_category DOS; reference:url,isc.sans.edu/forums/diary/SMBLoris+the+new+SMB+flaw/22662/; classtype:trojan-activity; sid:2024511; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Internal, signature_severity Major, created_at 2017_08_02, performance_impact Significant, updated_at 2017_08_03;)
` 

Name : **SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based)** 

Attack target : Client_and_Server

Description : Alerts on SMBloris packet

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,isc.sans.edu/forums/diary/SMBLoris+the+new+SMB+flaw/22662/

CVE reference : Not defined

Creation date : 2017-08-02

Last modified date : 2017-08-03

Rev version : 2

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2024584
`alert udp $EXTERNAL_NET 389 -> $HOME_NET 389 (msg:"ET DOS CLDAP Amplification Reflection (PoC based)"; dsize:52; content:"|30 84 00 00 00 2d 02 01 01 63 84 00 00 00 24 04 00 0a 01 00|"; fast_pattern; threshold:type both, count 100, seconds 60, track by_src; metadata: former_category DOS; reference:url,www.akamai.com/us/en/multimedia/documents/state-of-the-internet/cldap-threat-advisory.pdf; reference:url,packetstormsecurity.com/files/139561/LDAP-Amplication-Denial-Of-Service.html; classtype:attempted-dos; sid:2024584; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Linux, attack_target Server, deployment Perimeter, signature_severity Major, created_at 2017_08_16, performance_impact Significant, updated_at 2017_08_16;)
` 

Name : **CLDAP Amplification Reflection (PoC based)** 

Attack target : Server

Description : Detects usage of the default CLDAP DoS amplification PoC script available on Packet Storm Security.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,www.akamai.com/us/en/multimedia/documents/state-of-the-internet/cldap-threat-advisory.pdf|url,packetstormsecurity.com/files/139561/LDAP-Amplication-Denial-Of-Service.html

CVE reference : Not defined

Creation date : 2017-08-16

Last modified date : 2017-08-16

Rev version : 1

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2024585
`alert udp $EXTERNAL_NET any -> $HOME_NET 389 (msg:"ET DOS Potential CLDAP Amplification Reflection"; content:"objectclass0"; fast_pattern; threshold:type both, count 200, seconds 60, track by_src; metadata: former_category DOS; reference:url,www.akamai.com/us/en/multimedia/documents/state-of-the-internet/cldap-threat-advisory.pdf; reference:url,packetstormsecurity.com/files/139561/LDAP-Amplication-Denial-Of-Service.html; classtype:attempted-dos; sid:2024585; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Major, created_at 2017_08_16, performance_impact Significant, updated_at 2017_08_16;)
` 

Name : **Potential CLDAP Amplification Reflection** 

Attack target : Client_and_Server

Description : Detects potential CLDAP Amplification Reflection DoS based on thresholding and generic CLDAP query.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,www.akamai.com/us/en/multimedia/documents/state-of-the-internet/cldap-threat-advisory.pdf|url,packetstormsecurity.com/files/139561/LDAP-Amplication-Denial-Of-Service.html

CVE reference : Not defined

Creation date : 2017-08-16

Last modified date : 2017-08-16

Rev version : 1

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2025401
`alert udp $EXTERNAL_NET any -> any 11211 (msg:"ET DOS Possible Memcached DDoS Amplification Query (set)"; content:"|00 00 00 00 00 01 00|"; depth:7; fast_pattern; content:"|0d 0a|"; distance:0; within:20; isdataat:!1,relative; threshold: type both, count 100, seconds 60, track by_dst; flowbits:set,ET.memcached.ddos; metadata: former_category DOS; reference:url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/; classtype:attempted-dos; sid:2025401; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Linux, attack_target Server, deployment Perimeter, signature_severity Major, created_at 2018_03_01, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Possible Memcached DDoS Amplification Query (set)** 

Attack target : Server

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/

CVE reference : Not defined

Creation date : 2018-03-01

Last modified date : 2019-09-28

Rev version : 3

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025402
`alert udp any 11211 -> $EXTERNAL_NET any (msg:"ET DOS Possible Memcached DDoS Amplification Response Outbound"; flowbits:isset,ET.memcached.ddos; content:"STATS|20|pid"; depth:9; fast_pattern; threshold: type both, count 100, seconds 60, track by_dst; metadata: former_category DOS; reference:url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/; classtype:attempted-dos; sid:2025402; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Linux, attack_target Server, deployment Perimeter, signature_severity Major, created_at 2018_03_01, performance_impact Low, updated_at 2018_03_01;)
` 

Name : **Possible Memcached DDoS Amplification Response Outbound** 

Attack target : Server

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/

CVE reference : Not defined

Creation date : 2018-03-01

Last modified date : 2018-03-01

Rev version : 1

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025403
`alert udp $EXTERNAL_NET 11211 -> $HOME_NET any (msg:"ET DOS Possible Memcached DDoS Amplification Inbound"; content:"STATS|20|pid"; depth:9; fast_pattern; threshold: type both, count 100, seconds 60, track by_dst; metadata: former_category DOS; reference:url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/; classtype:attempted-dos; sid:2025403; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Linux, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_03_01, performance_impact Low, updated_at 2018_03_01;)
` 

Name : **Possible Memcached DDoS Amplification Inbound** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-dos

URL reference : url,blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/

CVE reference : Not defined

Creation date : 2018-03-01

Last modified date : 2018-03-01

Rev version : 1

Category : DOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2016322
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET DOS LibuPnP CVE-2012-5958 ST DeviceType Buffer Overflow"; content:"|0D 0A|ST|3a|"; nocase; pcre:"/^[^\r\n]*schemas\x3adevice\x3a[^\r\n\x3a]{181}/Ri"; content:"schemas|3a|device"; nocase; fast_pattern; reference:cve,CVE_2012-5958; reference:cve,CVE-2012-5962; classtype:attempted-dos; sid:2016322; rev:2; metadata:created_at 2013_01_31, updated_at 2019_10_07;)
` 

Name : **LibuPnP CVE-2012-5958 ST DeviceType Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,CVE_2012-5958|cve,CVE-2012-5962

CVE reference : Not defined

Creation date : 2013-01-31

Last modified date : 2019-10-07

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016324
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET DOS LibuPnP CVE-2012-5964 ST URN ServiceType Buffer Overflow"; content:"|0D 0A|ST|3a|"; nocase; pcre:"/^[^\r\n]*urn\x3aservice\x3a[^\r\n\x3a]{181}/Ri"; content:"urn|3a|service"; nocase; fast_pattern; reference:cve,CVE-2012-5964; classtype:attempted-dos; sid:2016324; rev:2; metadata:created_at 2013_01_31, updated_at 2019_10_07;)
` 

Name : **LibuPnP CVE-2012-5964 ST URN ServiceType Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,CVE-2012-5964

CVE reference : Not defined

Creation date : 2013-01-31

Last modified date : 2019-10-07

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016325
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET DOS LibuPnP CVE-2012-5965 ST URN DeviceType Buffer Overflow"; content:"|0D 0A|ST|3a|"; nocase; pcre:"/^[^\r\n]*urn\x3adevice\x3a[^\r\n\x3a]{181}/Ri"; content:"urn|3a|device"; nocase; fast_pattern; reference:cve,CVE-2012-5965; classtype:attempted-dos; sid:2016325; rev:2; metadata:created_at 2013_01_31, updated_at 2019_10_07;)
` 

Name : **LibuPnP CVE-2012-5965 ST URN DeviceType Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,CVE-2012-5965

CVE reference : Not defined

Creation date : 2013-01-31

Last modified date : 2019-10-07

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016326
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET DOS LibuPnP CVE-2012-5961 ST UDN Buffer Overflow"; content:"|0D 0A|ST|3a|"; nocase; pcre:"/^[^\r\n]*schemas\x3adevice\x3a[^\r\n\x3a]{1,180}\x3a[^\r\n\x3a]{181}/Ri"; content:"schemas|3a|device"; nocase; fast_pattern; reference:cve,CVE-2012-5961; classtype:attempted-dos; sid:2016326; rev:2; metadata:created_at 2013_01_31, updated_at 2019_10_07;)
` 

Name : **LibuPnP CVE-2012-5961 ST UDN Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,CVE-2012-5961

CVE reference : Not defined

Creation date : 2013-01-31

Last modified date : 2019-10-07

Rev version : 2

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020702
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS Bittorrent User-Agent inbound - possible DDOS"; flow:established,to_server; content:"Bittorrent"; http_user_agent; depth:10; threshold: type both, count 1, seconds 60, track by_src; reference:url,torrentfreak.com/zombie-pirate-bay-tracker-fuels-chinese-ddos-attacks-150124/; classtype:attempted-dos; sid:2020702; rev:3; metadata:created_at 2015_03_18, updated_at 2019_10_11;)
` 

Name : **Bittorrent User-Agent inbound - possible DDOS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,torrentfreak.com/zombie-pirate-bay-tracker-fuels-chinese-ddos-attacks-150124/

CVE reference : Not defined

Creation date : 2015-03-18

Last modified date : 2019-10-11

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018977
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DOS HOIC with booster outbound"; flow:to_server,established; content:"GET"; http_method; content:"If-Modified-Since|3a 20 20|"; http_raw_header; content:"Keep-Alive|3a 20 20|"; http_raw_header; content:"Connection|3a 20 20|"; http_raw_header; content:"User-Agent|3a 20 20|"; http_raw_header; http_start; content:"HTTP/1.0|0d 0a|Accept|3a 20|*/*|0d 0a|Accept-Language|3a 20|"; threshold: type both, count 1, seconds 60, track by_src; reference:md5,23fc64a5cac4406d7143ea26e8c4c7ab; reference:url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html; classtype:trojan-activity; sid:2018977; rev:4; metadata:created_at 2014_08_21, updated_at 2020_02_07;)
` 

Name : **HOIC with booster outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,23fc64a5cac4406d7143ea26e8c4c7ab|url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html

CVE reference : Not defined

Creation date : 2014-08-21

Last modified date : 2020-02-07

Rev version : 4

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018978
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS HOIC with booster inbound"; flow:to_server,established; content:"GET"; http_method; content:"If-Modified-Since|3a 20 20|"; http_raw_header; content:"Keep-Alive|3a 20 20|"; http_raw_header; content:"Connection|3a 20 20|"; http_raw_header; content:"User-Agent|3a 20 20|"; http_raw_header; http_start; content:"HTTP/1.0|0d 0a|Accept|3a 20|*/*|0d 0a|Accept-Language|3a 20|"; threshold: type both, count 1, seconds 60, track by_dst; reference:md5,23fc64a5cac4406d7143ea26e8c4c7ab; reference:url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html; classtype:trojan-activity; sid:2018978; rev:3; metadata:created_at 2014_08_21, updated_at 2020_02_07;)
` 

Name : **HOIC with booster inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,23fc64a5cac4406d7143ea26e8c4c7ab|url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html

CVE reference : Not defined

Creation date : 2014-08-21

Last modified date : 2020-02-07

Rev version : 3

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014153
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET DOS High Orbit Ion Cannon (HOIC) Attack Inbound Generic Detection Double Spaced UA"; flow:established,to_server; content:"User-Agent|3a 20 20|"; http_raw_header; fast_pattern; threshold: type both, track by_src, count 225, seconds 60; reference:url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html; classtype:attempted-dos; sid:2014153; rev:7; metadata:created_at 2012_01_27, updated_at 2020_03_11;)
` 

Name : **High Orbit Ion Cannon (HOIC) Attack Inbound Generic Detection Double Spaced UA** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html

CVE reference : Not defined

Creation date : 2012-01-27

Last modified date : 2020-03-11

Rev version : 7

Category : DOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

