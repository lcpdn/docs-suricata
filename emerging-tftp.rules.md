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



alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer"; content:"|00 03|"; depth:2; reference:url,doc.emergingthreats.net/2008117; classtype:policy-violation; sid:2008117; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008117
`alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer"; content:"|00 03|"; depth:2; reference:url,doc.emergingthreats.net/2008117; classtype:policy-violation; sid:2008117; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Outbound TFTP Data Transfer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2008117

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP ACK"; content:"|00 04|"; depth:2; reference:url,doc.emergingthreats.net/2008118; classtype:policy-violation; sid:2008118; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008118
`alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP ACK"; content:"|00 04|"; depth:2; reference:url,doc.emergingthreats.net/2008118; classtype:policy-violation; sid:2008118; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Outbound TFTP ACK** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2008118

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Error Message"; content:"|00 05|"; depth:2; reference:url,doc.emergingthreats.net/2008119; classtype:policy-violation; sid:2008119; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008119
`alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Error Message"; content:"|00 05|"; depth:2; reference:url,doc.emergingthreats.net/2008119; classtype:policy-violation; sid:2008119; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Outbound TFTP Error Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2008119

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any 69 (msg:"GPL TFTP GET filename overflow attempt"; content:"|00 01|"; depth:2; isdataat:100,relative; content:!"|00|"; within:100; reference:bugtraq,5328; reference:cve,2002-0813; classtype:attempted-admin; sid:2101941; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101941
`#alert udp any any -> any 69 (msg:"GPL TFTP GET filename overflow attempt"; content:"|00 01|"; depth:2; isdataat:100,relative; content:!"|00|"; within:100; reference:bugtraq,5328; reference:cve,2002-0813; classtype:attempted-admin; sid:2101941; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GET filename overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,5328|cve,2002-0813

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP root directory"; content:"|00 01|/"; depth:3; reference:cve,1999-0183; classtype:bad-unknown; sid:2100520; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100520
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP root directory"; content:"|00 01|/"; depth:3; reference:cve,1999-0183; classtype:bad-unknown; sid:2100520; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **root directory** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : cve,1999-0183

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP parent directory"; content:".."; offset:2; reference:cve,1999-0183; reference:cve,2002-1209; classtype:bad-unknown; sid:2100519; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100519
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP parent directory"; content:".."; offset:2; reference:cve,1999-0183; reference:cve,2002-1209; classtype:bad-unknown; sid:2100519; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **parent directory** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : cve,1999-0183|cve,2002-1209

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP Put"; content:"|00 02|"; depth:2; reference:cve,1999-0183; classtype:bad-unknown; sid:2100518; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100518
`alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP Put"; content:"|00 02|"; depth:2; reference:cve,1999-0183; classtype:bad-unknown; sid:2100518; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Put** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : cve,1999-0183

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any 69 (msg:"GPL TFTP PUT filename overflow attempt"; content:"|00 02|"; depth:2; isdataat:100,relative; content:!"|00|"; within:100; reference:bugtraq,7819; reference:bugtraq,8505; reference:cve,2003-0380; classtype:attempted-admin; sid:2102337; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102337
`#alert udp any any -> any 69 (msg:"GPL TFTP PUT filename overflow attempt"; content:"|00 02|"; depth:2; isdataat:100,relative; content:!"|00|"; within:100; reference:bugtraq,7819; reference:bugtraq,8505; reference:cve,2003-0380; classtype:attempted-admin; sid:2102337; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PUT filename overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,7819|bugtraq,8505|cve,2003-0380

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP NULL command attempt"; content:"|00 00|"; depth:2; reference:bugtraq,7575; classtype:bad-unknown; sid:2102336; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102336
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP NULL command attempt"; content:"|00 00|"; depth:2; reference:bugtraq,7575; classtype:bad-unknown; sid:2102336; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NULL command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,7575

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any 69 (msg:"GPL TFTP GET shadow"; content:"|00 01|"; depth:2; content:"shadow"; offset:2; nocase; classtype:successful-admin; sid:2101442; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101442
`alert udp any any -> any 69 (msg:"GPL TFTP GET shadow"; content:"|00 01|"; depth:2; content:"shadow"; offset:2; nocase; classtype:successful-admin; sid:2101442; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GET shadow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any 69 (msg:"GPL TFTP GET passwd"; content:"|00 01|"; depth:2; content:"passwd"; offset:2; nocase; classtype:successful-admin; sid:2101443; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101443
`alert udp any any -> any 69 (msg:"GPL TFTP GET passwd"; content:"|00 01|"; depth:2; content:"passwd"; offset:2; nocase; classtype:successful-admin; sid:2101443; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GET passwd** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP Get"; content:"|00 01|"; depth:2; classtype:bad-unknown; sid:2101444; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101444
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP Get"; content:"|00 01|"; depth:2; classtype:bad-unknown; sid:2101444; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Get** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any 69 (msg:"GPL TFTP GET Admin.dll"; content:"|00 01|"; depth:2; content:"admin.dll"; offset:2; nocase; reference:url,www.cert.org/advisories/CA-2001-26.html; classtype:successful-admin; sid:2101289; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101289
`alert udp any any -> any 69 (msg:"GPL TFTP GET Admin.dll"; content:"|00 01|"; depth:2; content:"admin.dll"; offset:2; nocase; reference:url,www.cert.org/advisories/CA-2001-26.html; classtype:successful-admin; sid:2101289; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GET Admin.dll** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,www.cert.org/advisories/CA-2001-26.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any 69 (msg:"GPL TFTP GET nc.exe"; content:"|00 01|"; depth:2; content:"nc.exe"; offset:2; nocase; classtype:successful-admin; sid:2101441; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101441
`alert udp any any -> any 69 (msg:"GPL TFTP GET nc.exe"; content:"|00 01|"; depth:2; content:"nc.exe"; offset:2; nocase; classtype:successful-admin; sid:2101441; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GET nc.exe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP MISC TFTP32 Get Format string attempt"; content:"|00 01 25 2E|"; depth:4; reference:url,www.securityfocus.com/archive/1/422405/30/0/threaded; reference:url,www.critical.lt/?vulnerabilities/200; classtype:attempted-admin; sid:2101222; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101222
`alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"GPL TFTP MISC TFTP32 Get Format string attempt"; content:"|00 01 25 2E|"; depth:4; reference:url,www.securityfocus.com/archive/1/422405/30/0/threaded; reference:url,www.critical.lt/?vulnerabilities/200; classtype:attempted-admin; sid:2101222; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MISC TFTP32 Get Format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.securityfocus.com/archive/1/422405/30/0/threaded|url,www.critical.lt/?vulnerabilities/200

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : TFTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"ET TFTP TFTPGUI Long Transport Mode Buffer Overflow"; content:"|00 02|"; depth:2; content:"|00|"; distance:0; within:50; content:!"|00|"; distance:0; within:9; reference:url,www.exploit-db.com/exploits/12482/; reference:url,packetstormsecurity.org/files/view/96395/tftputilgui-dos.rb.txt; reference:url,securityfocus.com/bid/39872/; classtype:attempted-dos; sid:2012051; rev:2; metadata:created_at 2010_12_14, updated_at 2010_12_14;)

# 2012051
`#alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"ET TFTP TFTPGUI Long Transport Mode Buffer Overflow"; content:"|00 02|"; depth:2; content:"|00|"; distance:0; within:50; content:!"|00|"; distance:0; within:9; reference:url,www.exploit-db.com/exploits/12482/; reference:url,packetstormsecurity.org/files/view/96395/tftputilgui-dos.rb.txt; reference:url,securityfocus.com/bid/39872/; classtype:attempted-dos; sid:2012051; rev:2; metadata:created_at 2010_12_14, updated_at 2010_12_14;)
` 

Name : **TFTPGUI Long Transport Mode Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.exploit-db.com/exploits/12482/|url,packetstormsecurity.org/files/view/96395/tftputilgui-dos.rb.txt|url,securityfocus.com/bid/39872/

CVE reference : Not defined

Creation date : 2010-12-14

Last modified date : 2010-12-14

Rev version : 2

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> [$EXTERNAL_NET,!255.255.255.255] 69 (msg:"ET TFTP Outbound TFTP Read Request"; content:"|00 01|"; depth:2; reference:url,doc.emergingthreats.net/2008120; classtype:policy-violation; sid:2008120; rev:4; metadata:created_at 2010_07_30, updated_at 2017_01_12;)

# 2008120
`alert udp $HOME_NET any -> [$EXTERNAL_NET,!255.255.255.255] 69 (msg:"ET TFTP Outbound TFTP Read Request"; content:"|00 01|"; depth:2; reference:url,doc.emergingthreats.net/2008120; classtype:policy-violation; sid:2008120; rev:4; metadata:created_at 2010_07_30, updated_at 2017_01_12;)
` 

Name : **Outbound TFTP Read Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2008120

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-01-12

Rev version : 4

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> [$EXTERNAL_NET,!255.255.255.255] 69 (msg:"ET TFTP Outbound TFTP Write Request"; content:"|00 02|"; depth:2; reference:url,doc.emergingthreats.net/2008116; classtype:policy-violation; sid:2008116; rev:4; metadata:created_at 2010_07_30, updated_at 2017_01_25;)

# 2008116
`alert udp $HOME_NET any -> [$EXTERNAL_NET,!255.255.255.255] 69 (msg:"ET TFTP Outbound TFTP Write Request"; content:"|00 02|"; depth:2; reference:url,doc.emergingthreats.net/2008116; classtype:policy-violation; sid:2008116; rev:4; metadata:created_at 2010_07_30, updated_at 2017_01_25;)
` 

Name : **Outbound TFTP Write Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2008116

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-01-25

Rev version : 4

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer with Cisco config"; content:"|00 03|"; depth:2; content:"|0a 21 20|version|20|"; distance:2; within:12; metadata: former_category TFTP; classtype:policy-violation; sid:2015857; rev:5; metadata:created_at 2012_10_31, updated_at 2017_07_19;)

# 2015857
`alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer with Cisco config"; content:"|00 03|"; depth:2; content:"|0a 21 20|version|20|"; distance:2; within:12; metadata: former_category TFTP; classtype:policy-violation; sid:2015857; rev:5; metadata:created_at 2012_10_31, updated_at 2017_07_19;)
` 

Name : **Outbound TFTP Data Transfer with Cisco config** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-31

Last modified date : 2017-07-19

Rev version : 5

Category : TFTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer With Cisco Config 2"; content:"|00 03|"; depth:2; content:"NVRAM config last update"; distance:0; metadata: former_category TFTP; classtype:policy-violation; sid:2024481; rev:2; metadata:affected_product Cisco_ASA, affected_product Cisco_PIX, affected_product CISCO_Catalyst, attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2017_07_19, performance_impact Moderate, updated_at 2017_07_19;)

# 2024481
`alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET TFTP Outbound TFTP Data Transfer With Cisco Config 2"; content:"|00 03|"; depth:2; content:"NVRAM config last update"; distance:0; metadata: former_category TFTP; classtype:policy-violation; sid:2024481; rev:2; metadata:affected_product Cisco_ASA, affected_product Cisco_PIX, affected_product CISCO_Catalyst, attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2017_07_19, performance_impact Moderate, updated_at 2017_07_19;)
` 

Name : **Outbound TFTP Data Transfer With Cisco Config 2** 

Attack target : Networking_Equipment

Description : Not defined

Tags : Not defined

Affected products : Cisco_ASA

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-07-19

Last modified date : 2017-07-19

Rev version : 2

Category : TFTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate



