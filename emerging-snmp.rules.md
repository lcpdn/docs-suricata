# Emerging Threats 

#

# This distribution may contain rules under two different licenses. 

#

#  Rules with sids 1 through 3464, and 100000000 through 100000908 are under the GPLv2.

#  A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html

#

#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License 

#  as follows:

#

#*************************************************************

#  Copyright (c) 2003-2019, Emerging Threats

#  All rights reserved.

#  

#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 

#  following conditions are met:

#  

#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 

#    disclaimer.

#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 

#    following disclaimer in the documentation and/or other materials provided with the distribution.

#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 

#    from this software without specific prior written permission.

#  

#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 

#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 

#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 

#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 

#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 

#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 

#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

#

#*************************************************************

#

#

#

#



# This Ruleset is EmergingThreats Open optimized for suricata-4.0-enhanced.



#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 trap port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002880; classtype:attempted-dos; sid:2002880; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002880
`#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 trap port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002880; classtype:attempted-dos; sid:2002880; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv1 trap port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002880

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv2 trap port"; content:"|02 01|"; depth:2; byte_test:1,>,0,0,relative; byte_test:1,<,3,0,relative; byte_test:1,>,159,9,relative; byte_test:1,<,167,9,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002881; classtype:attempted-dos; sid:2002881; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002881
`#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv2 trap port"; content:"|02 01|"; depth:2; byte_test:1,>,0,0,relative; byte_test:1,<,3,0,relative; byte_test:1,>,159,9,relative; byte_test:1,<,167,9,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002881; classtype:attempted-dos; sid:2002881; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv2 trap port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002881

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv3 trap port"; content:"|02 01 03|"; depth:3; byte_test:1,>,159,43,relative; byte_test:1,<,167,43,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002882; classtype:attempted-dos; sid:2002882; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002882
`#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv3 trap port"; content:"|02 01 03|"; depth:3; byte_test:1,>,159,43,relative; byte_test:1,<,167,43,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002882; classtype:attempted-dos; sid:2002882; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv3 trap port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002882

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 random port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002926; classtype:attempted-dos; sid:2002926; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002926
`#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 random port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002926; classtype:attempted-dos; sid:2002926; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv1 random port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002926

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv2 random port"; content:"|02 01|"; depth:2; byte_test:1,>,0,0,relative; byte_test:1,<,3,0,relative; byte_test:1,>,159,9,relative; byte_test:1,<,167,9,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002927; classtype:attempted-dos; sid:2002927; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002927
`#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv2 random port"; content:"|02 01|"; depth:2; byte_test:1,>,0,0,relative; byte_test:1,<,3,0,relative; byte_test:1,>,159,9,relative; byte_test:1,<,167,9,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002927; classtype:attempted-dos; sid:2002927; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv2 random port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002927

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv3 random port"; content:"|02 01 03|"; depth:3; byte_test:1,>,159,43,relative; byte_test:1,<,167,43,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002928; classtype:attempted-dos; sid:2002928; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002928
`#alert udp $EXTERNAL_NET !161 -> $HOME_NET 49152: (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv3 random port"; content:"|02 01 03|"; depth:3; byte_test:1,>,159,43,relative; byte_test:1,<,167,43,relative; reference:cve,2004-0714; reference:bugtraq,10186; reference:url,doc.emergingthreats.net/bin/view/Main/2002928; classtype:attempted-dos; sid:2002928; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv3 random port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2004-0714|bugtraq,10186|url,doc.emergingthreats.net/bin/view/Main/2002928

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI"; content:"ILMI"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml; reference:url,doc.emergingthreats.net/2011011; classtype:attempted-admin; sid:2011011; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011011
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI"; content:"ILMI"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml; reference:url,doc.emergingthreats.net/2011011; classtype:attempted-admin; sid:2011011; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml|url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml|url,doc.emergingthreats.net/2011011

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI"; flow:to_server,established; content:"ILMI"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml; reference:url,doc.emergingthreats.net/2011012; classtype:attempted-admin; sid:2011012; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011012
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI"; flow:to_server,established; content:"ILMI"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml; reference:url,doc.emergingthreats.net/2011012; classtype:attempted-admin; sid:2011012; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml|url,www.cisco.com/warp/public/707/cisco-sa-20010227-ios-snmp-ilmi.shtml|url,doc.emergingthreats.net/2011012

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis"; content:"cable-docsis"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm; reference:url,www.kb.cert.org/vuls/id/840665; reference:cve,2004-1776; reference:url,doc.emergingthreats.net/2011013; classtype:attempted-admin; sid:2011013; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011013
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis"; content:"cable-docsis"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm; reference:url,www.kb.cert.org/vuls/id/840665; reference:cve,2004-1776; reference:url,doc.emergingthreats.net/2011013; classtype:attempted-admin; sid:2011013; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml|url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm|url,www.kb.cert.org/vuls/id/840665|cve,2004-1776|url,doc.emergingthreats.net/2011013

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis"; flow:to_server,established; content:"cable-docsis"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm; reference:url,www.kb.cert.org/vuls/id/840665; reference:cve,2004-1776; reference:url,doc.emergingthreats.net/2011014; classtype:attempted-admin; sid:2011014; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011014
`alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis"; flow:to_server,established; content:"cable-docsis"; nocase; reference:url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml; reference:url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm; reference:url,www.kb.cert.org/vuls/id/840665; reference:cve,2004-1776; reference:url,doc.emergingthreats.net/2011014; classtype:attempted-admin; sid:2011014; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Attempted TCP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String cable-docsis** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml|url,www.iss.net/security_center/reference/vuln/cisco-ios-cable-docsis.htm|url,www.kb.cert.org/vuls/id/840665|cve,2004-1776|url,doc.emergingthreats.net/2011014

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP null community string attempt"; content:"|04 01 00|"; depth:15; offset:5; reference:bugtraq,2112; reference:bugtraq,8974; reference:cve,1999-0517; classtype:misc-attack; sid:2101892; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101892
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP null community string attempt"; content:"|04 01 00|"; depth:15; offset:5; reference:bugtraq,2112; reference:bugtraq,8974; reference:cve,1999-0517; classtype:misc-attack; sid:2101892; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **null community string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|bugtraq,8974|cve,1999-0517

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP missing community string attempt"; content:"|04 00|"; depth:15; offset:5; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2101893; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101893
`#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP missing community string attempt"; content:"|04 00|"; depth:15; offset:5; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2101893; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **missing community string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|cve,1999-0517

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP request udp";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101417; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101417
`#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP request udp";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101417; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **request udp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP trap tcp"; flow:stateless; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101420; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101420
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP trap tcp"; flow:stateless; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101420; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **trap tcp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP trap udp";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101419; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101419
`#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP trap udp";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101419; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **trap udp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> 255.255.255.255 161 (msg:"GPL SNMP Broadcast request";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101415; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101415
`#alert udp any any -> 255.255.255.255 161 (msg:"GPL SNMP Broadcast request";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101415; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Broadcast request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> 255.255.255.255 162 (msg:"GPL SNMP broadcast trap";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101416; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101416
`#alert udp any any -> 255.255.255.255 162 (msg:"GPL SNMP broadcast trap";  reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101416; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **broadcast trap** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 161:162 (msg:"GPL SNMP community string buffer overflow attempt with evasion"; content:" |04 82 01 00|"; depth:5; offset:7; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; reference:url,www.cert.org/advisories/CA-2002-03.html; classtype:misc-attack; sid:2101422; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101422
`#alert udp $EXTERNAL_NET any -> $HOME_NET 161:162 (msg:"GPL SNMP community string buffer overflow attempt with evasion"; content:" |04 82 01 00|"; depth:5; offset:7; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; reference:url,www.cert.org/advisories/CA-2002-03.html; classtype:misc-attack; sid:2101422; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **community string buffer overflow attempt with evasion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013|url,www.cert.org/advisories/CA-2002-03.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 161:162 (msg:"GPL SNMP SNMP community string buffer overflow attempt"; content:"|02 01 00 04 82 01 00|"; offset:4; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; reference:url,www.cert.org/advisories/CA-2002-03.html; classtype:misc-attack; sid:2101409; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101409
`#alert udp $EXTERNAL_NET any -> $HOME_NET 161:162 (msg:"GPL SNMP SNMP community string buffer overflow attempt"; content:"|02 01 00 04 82 01 00|"; offset:4; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; reference:url,www.cert.org/advisories/CA-2002-03.html; classtype:misc-attack; sid:2101409; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SNMP community string buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013|url,www.cert.org/advisories/CA-2002-03.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP private access tcp"; flow:to_server,established; content:"private"; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101414; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101414
`alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP private access tcp"; flow:to_server,established; content:"private"; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101414; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **private access tcp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP public access tcp"; flow:to_server,established; content:"public"; reference:bugtraq,2112; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,7212; reference:cve,1999-0517; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101412; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101412
`alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP public access tcp"; flow:to_server,established; content:"public"; reference:bugtraq,2112; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,7212; reference:cve,1999-0517; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101412; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **public access tcp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,2112|bugtraq,4088|bugtraq,4089|bugtraq,7212|cve,1999-0517|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP request tcp"; flow:stateless; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101418; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101418
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP request tcp"; flow:stateless; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101418; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **request tcp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 1"; content:"|30|"; depth:1; byte_test:1,!&,0x80,0,relative,big; content:"|02|"; distance:1; within:1; byte_test:1,!&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016178; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)

# 2016178
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 1"; content:"|30|"; depth:1; byte_test:1,!&,0x80,0,relative,big; content:"|02|"; distance:1; within:1; byte_test:1,!&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016178; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **missing community string attempt 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|cve,1999-0517

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 2"; content:"|30|"; depth:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|02|"; distance:-129; within:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; distance:-129; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016179; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)

# 2016179
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 2"; content:"|30|"; depth:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|02|"; distance:-129; within:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; distance:-129; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016179; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **missing community string attempt 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|cve,1999-0517

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 3"; content:"|30|"; depth:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|02|"; distance:-129; within:1; byte_test:1,!&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; within:2; metadata: former_category SNMP; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016180; rev:2; metadata:created_at 2013_01_09, updated_at 2017_08_24;)

# 2016180
`#alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 3"; content:"|30|"; depth:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|02|"; distance:-129; within:1; byte_test:1,!&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; within:2; metadata: former_category SNMP; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016180; rev:2; metadata:created_at 2013_01_09, updated_at 2017_08_24;)
` 

Name : **missing community string attempt 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|cve,1999-0517

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2017-08-24

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 4"; content:"|30|"; depth:1; byte_test:1,!&,0x80,0,relative,big; content:"|02|"; distance:1; within:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; distance:-129; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016181; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)

# 2016181
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP missing community string attempt 4"; content:"|30|"; depth:1; byte_test:1,!&,0x80,0,relative,big; content:"|02|"; distance:1; within:1; byte_test:1,&,0x80,0,relative,big; byte_jump:1,0,relative; content:"|04 00|"; distance:-129; within:2; reference:bugtraq,2112; reference:cve,1999-0517; classtype:misc-attack; sid:2016181; rev:2; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **missing community string attempt 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,2112|cve,1999-0517

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 2

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 trap port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative;  metadata: former_category SNMP; classtype:attempted-dos; sid:2027890; rev:1; metadata:created_at 2019_08_15, updated_at 2019_08_16;)

# 2027890
`#alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"ET SNMP Cisco Non-Trap PDU request on SNMPv1 trap port"; content:"|02 01 00|"; depth:3; byte_test:1,>,159,8,relative; byte_test:1,<,164,8,relative;  metadata: former_category SNMP; classtype:attempted-dos; sid:2027890; rev:1; metadata:created_at 2019_08_15, updated_at 2019_08_16;)
` 

Name : **Cisco Non-Trap PDU request on SNMPv1 trap port** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-08-15

Last modified date : 2019-08-16

Rev version : 1

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP private access udp"; content:"private"; fast_pattern; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:bugtraq,7212; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101413; rev:12; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101413
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP private access udp"; content:"private"; fast_pattern; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:bugtraq,7212; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101413; rev:12; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **private access udp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,4088|bugtraq,4089|bugtraq,4132|bugtraq,7212|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 12

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP public access udp"; content:"public"; fast_pattern; reference:bugtraq,2112; reference:bugtraq,4088; reference:bugtraq,4089; reference:cve,1999-0517; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101411; rev:13; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101411
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP public access udp"; content:"public"; fast_pattern; reference:bugtraq,2112; reference:bugtraq,4088; reference:bugtraq,4089; reference:cve,1999-0517; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:2101411; rev:13; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **public access udp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,2112|bugtraq,4088|bugtraq,4089|cve,1999-0517|cve,2002-0012|cve,2002-0013

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 13

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP PROTOS test-suite-trap-app attempt"; content:"08|02 01 00 04 06|public|A4|+|06|"; fast_pattern; reference:url,www.ee.oulu.fi/research/ouspg/protos/testing/c06/snmpv1/index.html; classtype:misc-attack; sid:2101427; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101427
`alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP PROTOS test-suite-trap-app attempt"; content:"08|02 01 00 04 06|public|A4|+|06|"; fast_pattern; reference:url,www.ee.oulu.fi/research/ouspg/protos/testing/c06/snmpv1/index.html; classtype:misc-attack; sid:2101427; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **PROTOS test-suite-trap-app attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,www.ee.oulu.fi/research/ouspg/protos/testing/c06/snmpv1/index.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 6

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP SNMP NT UserList"; content:"+|06 10|@|14 D1 02 19|"; fast_pattern; reference:nessus,10546; classtype:attempted-recon; sid:2100516; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2100516
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"GPL SNMP SNMP NT UserList"; content:"+|06 10|@|14 D1 02 19|"; fast_pattern; reference:nessus,10546; classtype:attempted-recon; sid:2100516; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **SNMP NT UserList** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10546

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any 161 (msg:"ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY)"; content:"|2b 06 01 04 01 09 09 60 01 01 01 01|"; fast_pattern; classtype:policy-violation; sid:2015856; rev:6; metadata:created_at 2012_10_31, updated_at 2019_10_07;)

# 2015856
`alert udp any any -> any 161 (msg:"ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY)"; content:"|2b 06 01 04 01 09 09 60 01 01 01 01|"; fast_pattern; classtype:policy-violation; sid:2015856; rev:6; metadata:created_at 2012_10_31, updated_at 2019_10_07;)
` 

Name : **Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-31

Last modified date : 2019-10-07

Rev version : 6

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Samsung Printer SNMP Hardcode RW Community String"; content:"s!a@m#n$p%c"; fast_pattern; reference:url,www.l8security.com/post/36715280176/vu-281284-samsung-printer-snmp-backdoor; classtype:attempted-admin; sid:2015959; rev:3; metadata:created_at 2012_11_28, updated_at 2019_10_07;)

# 2015959
`alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"ET SNMP Samsung Printer SNMP Hardcode RW Community String"; content:"s!a@m#n$p%c"; fast_pattern; reference:url,www.l8security.com/post/36715280176/vu-281284-samsung-printer-snmp-backdoor; classtype:attempted-admin; sid:2015959; rev:3; metadata:created_at 2012_11_28, updated_at 2019_10_07;)
` 

Name : **Samsung Printer SNMP Hardcode RW Community String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.l8security.com/post/36715280176/vu-281284-samsung-printer-snmp-backdoor

CVE reference : Not defined

Creation date : 2012-11-28

Last modified date : 2019-10-07

Rev version : 3

Category : SNMP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP SNMP trap Format String detected"; content:"%s"; fast_pattern; reference:bugtraq,16267; reference:cve,2006-0250; reference:url,www.osvdb.org/displayvuln.php?osvdb_id=22493; classtype:attempted-recon; sid:2100227; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2100227
`alert udp $EXTERNAL_NET any -> $HOME_NET 162 (msg:"GPL SNMP SNMP trap Format String detected"; content:"%s"; fast_pattern; reference:bugtraq,16267; reference:cve,2006-0250; reference:url,www.osvdb.org/displayvuln.php?osvdb_id=22493; classtype:attempted-recon; sid:2100227; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **SNMP trap Format String detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,16267|cve,2006-0250|url,www.osvdb.org/displayvuln.php?osvdb_id=22493

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SNMP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



