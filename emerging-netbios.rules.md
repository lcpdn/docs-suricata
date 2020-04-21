# 2009886
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS Remote SMB2.0 DoS Exploit"; flow:to_server,established; content:"|ff|SMB|72 00 00 00 00 18 53 c8|"; offset:4; content:!"|00 00|"; within:2; reference:url,securityreason.com/exploitalert/7138; reference:url,doc.emergingthreats.net/2009886; classtype:attempted-dos; sid:2009886; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Remote SMB2.0 DoS Exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,securityreason.com/exploitalert/7138|url,doc.emergingthreats.net/2009886

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000046
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS MS04011 Lsasrv.dll RPC exploit (Win2k)"; flow: to_server,established; content:"|00 00 00 00 9A A8 40 00 01 00 00 00 00 00 00 00|"; content:"|01 0000 00 00 00 00 00 9A A8 40 00 01 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2000046; reference:cve,2003-0533; classtype:misc-activity; sid:2000046; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MS04011 Lsasrv.dll RPC exploit (Win2k)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000046|cve,2003-0533

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000033
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS MS04011 Lsasrv.dll RPC exploit (WinXP)"; flow: to_server,established; content:"|95 14 40 00 03 00 00 00 7C 70 40 00 01|"; content:"|78 85 13 00 AB5B A6 E9 31 31|"; reference:url,doc.emergingthreats.net/bin/view/Main/2000033; reference:cve,2003-0533; classtype:misc-activity; sid:2000033; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MS04011 Lsasrv.dll RPC exploit (WinXP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000033|cve,2003-0533

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002064
`#alert tcp $HOME_NET 445 -> $EXTERNAL_NET any (msg:"ET NETBIOS ms05-011 exploit"; flow:from_server,established; content:"|00|"; depth:1; content:"|FF|SMB|32|"; depth:9; offset:4; content: "|ff ff ff ff 00 00 00 00 ff|"; offset: 132; depth: 141; reference:bugtraq,12484; reference:url,www.frsirt.com/exploits/20050623.mssmb_poc.c.php; reference:url,doc.emergingthreats.net/bin/view/Main/2002064; classtype:attempted-admin; sid:2002064; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ms05-011 exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,12484|url,www.frsirt.com/exploits/20050623.mssmb_poc.c.php|url,doc.emergingthreats.net/bin/view/Main/2002064

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002186
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS SMB-DS Microsoft Windows 2000 Plug and Play Vulnerability"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"|2600|"; depth:2; offset:65; content:"|67157a76|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx; reference:url,isc.sans.org/diary.php?date=2005-08-14; reference:url,doc.emergingthreats.net/bin/view/Main/2002186; classtype:attempted-admin; sid:2002186; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB-DS Microsoft Windows 2000 Plug and Play Vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx|url,isc.sans.org/diary.php?date=2005-08-14|url,doc.emergingthreats.net/bin/view/Main/2002186

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002199
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS SMB-DS DCERPC PnP HOD bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; distance:4; content:"|0B|"; within:1; distance:1; content:"|40 4E 9F 8D 3D A0 CE 11 8F 69 08 00 3E 30 05 1B|"; flowbits:set,netbios.pnp.bind.attempt; flowbits:noalert; reference:url,doc.emergingthreats.net/bin/view/Main/2002199; classtype:protocol-command-decode; sid:2002199; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB-DS DCERPC PnP HOD bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002199

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002200
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS SMB-DS DCERPC PnP bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; distance:2; content:"|0B|"; within:1; distance:1; content:"|40 4E 9F 8D 3D A0 CE 11 8F 69 08 00 3E 30 05 1B|"; flowbits:set,netbios.pnp.bind.attempt; flowbits:noalert; reference:url,doc.emergingthreats.net/bin/view/Main/2002200; classtype:protocol-command-decode; sid:2002200; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB-DS DCERPC PnP bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002200

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002201
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS SMB-DS DCERPC PnP QueryResConfList exploit attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|36 00|"; within:2; distance:26; pcre:"/(\x00\\\x00.*?){2}\x00{2}\xFF{2}.{128,}[\x04-\xFF][\x00-\xFF]{3}\x00{4}$/Rs"; flowbits:isset,netbios.pnp.bind.attempt; reference:cve,CAN-2005-1983; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx; reference:url,doc.emergingthreats.net/bin/view/Main/2002201; classtype:attempted-admin; sid:2002201; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB-DS DCERPC PnP QueryResConfList exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CAN-2005-1983|url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx|url,doc.emergingthreats.net/bin/view/Main/2002201

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002202
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"ET NETBIOS SMB DCERPC PnP bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00 0B|"; within:10; distance:4; byte_test:1,&,16,1,relative; content:"|40 4E 9F 8D 3D A0 CE 11 8F 69 08 00 3E 30 05 1B|"; flowbits:set,netbios.pnp.bind.attempt; flowbits:noalert; reference:url,doc.emergingthreats.net/bin/view/Main/2002202; classtype:protocol-command-decode; sid:2002202; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB DCERPC PnP bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002202

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002203
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"ET NETBIOS SMB DCERPC PnP QueryResConfList exploit attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00 00|"; within:10; distance:4; nocase; content:"|36 00|"; within:2; distance:19; pcre:"/(\x00\\\x00.*?){2}\x00{2}\xFF{2}.{128,}[\x04-\xFF][\x00-\xFF]{3}\x00{4}$/Rs"; flowbits:isset,netbios.pnp.bind.attempt; reference:cve,CAN-2005-1983; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx; reference:url,doc.emergingthreats.net/bin/view/Main/2002203; classtype:attempted-admin; sid:2002203; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SMB DCERPC PnP QueryResConfList exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CAN-2005-1983|url,www.microsoft.com/technet/security/Bulletin/MS05-039.mspx|url,doc.emergingthreats.net/bin/view/Main/2002203

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003081
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"ET NETBIOS NETBIOS SMB DCERPC NetrpPathCanonicalize request (possible MS06-040)"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB|25|"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00|"; within:9; distance:4; content:"|1f 00|"; distance:20; within:2; reference:url,www.microsoft.com/technet/security/bulletin/MS06-040.mspx; reference:url,doc.emergingthreats.net/bin/view/Main/2003081; classtype:misc-attack; sid:2003081; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NETBIOS SMB DCERPC NetrpPathCanonicalize request (possible MS06-040)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,www.microsoft.com/technet/security/bulletin/MS06-040.mspx|url,doc.emergingthreats.net/bin/view/Main/2003081

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003082
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS NETBIOS SMB-DS DCERPC NetrpPathCanonicalize request (possible MS06-040)"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB|25|"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00|"; within:9; distance:4; content:"|1f 00|"; distance:20; within:2; reference:url,www.microsoft.com/technet/security/bulletin/MS06-040.mspx; reference:url,doc.emergingthreats.net/bin/view/Main/2003082; classtype:misc-attack; sid:2003082; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NETBIOS SMB-DS DCERPC NetrpPathCanonicalize request (possible MS06-040)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,www.microsoft.com/technet/security/bulletin/MS06-040.mspx|url,doc.emergingthreats.net/bin/view/Main/2003082

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008690
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (1)"; content:"|0B|"; offset:2; depth:1; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008690; classtype:attempted-admin; sid:2008690; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008690

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008691
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (2)"; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"..|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008691; classtype:attempted-admin; sid:2008691; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008691

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008692
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (3)"; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008692; classtype:attempted-admin; sid:2008692; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (3)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008692

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008693
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (4)"; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008693; classtype:attempted-admin; sid:2008693; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (4)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008693

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008694
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (5)"; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008694; classtype:attempted-admin; sid:2008694; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008694

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008696
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (7)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"..|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008696; classtype:attempted-admin; sid:2008696; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (7)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008696

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008697
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (8)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008697; classtype:attempted-admin; sid:2008697; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (8)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008697

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008698
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (9)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008698; classtype:attempted-admin; sid:2008698; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (9)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008698

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008699
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (10)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008699; classtype:attempted-admin; sid:2008699; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (10)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008699

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008700
`alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 - Known Exploit Instance"; content:"|00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 87|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008700; classtype:attempted-admin; sid:2008700; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 - Known Exploit Instance** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008700

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008701
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (11)"; flow:established,to_server; content:"|0B|"; offset:2; depth:1; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008701; classtype:attempted-admin; sid:2008701; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (11)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008701

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008702
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (12)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008702; classtype:attempted-admin; sid:2008702; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (12)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008702

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008703
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (13)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"/../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008703; classtype:attempted-admin; sid:2008703; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (13)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008703

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008704
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (14)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008704; classtype:attempted-admin; sid:2008704; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (14)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008704

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008705
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (15)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008705; classtype:attempted-admin; sid:2008705; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (15)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008705

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008706
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (16)"; flow:established,to_server; content:"|0B|"; offset:2; depth:1; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008706; classtype:attempted-admin; sid:2008706; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (16)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008706

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008707
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (17)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"..|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008707; classtype:attempted-admin; sid:2008707; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (17)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008707

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008708
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (18)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008708; classtype:attempted-admin; sid:2008708; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (18)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008708

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008709
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (19)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008709; classtype:attempted-admin; sid:2008709; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (19)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008709

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008710
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (20)"; flow:established,to_server; content:"|1F 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008710; classtype:attempted-admin; sid:2008710; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (20)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008710

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008712
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (22)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008712; classtype:attempted-admin; sid:2008712; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (22)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008712

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008713
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (23)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"/../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008713; classtype:attempted-admin; sid:2008713; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (23)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008713

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008714
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (24)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008714; classtype:attempted-admin; sid:2008714; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (24)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008714

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008715
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (25)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008715; classtype:attempted-admin; sid:2008715; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (25)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008715

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008717
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (27)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"..|5C|..|5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008717; classtype:attempted-admin; sid:2008717; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (27)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008717

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008718
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (28)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008718; classtype:attempted-admin; sid:2008718; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (28)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008718

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008719
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (29)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 2F 00 2E 00 2E 00 2F|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008719; classtype:attempted-admin; sid:2008719; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (29)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008719

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008720
`alert tcp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (30)"; flow:established,to_server; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"|00 2E 00 2E 00 5C 00 2E 00 2E 00 5C|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008720; classtype:attempted-admin; sid:2008720; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (30)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008720

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008721
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 - Known Exploit Instance (2)"; flow:established,to_server; content:"|00 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 87|"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008721; classtype:attempted-admin; sid:2008721; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 - Known Exploit Instance (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx|cve,2008-4250|url,www.kb.cert.org/vuls/id/827267|url,doc.emergingthreats.net/bin/view/Main/2008721

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000017
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"ET NETBIOS NII Microsoft ASN.1 Library Buffer Overflow Exploit"; flow: to_server,established; content:"|A1 05 23 03 03 01 07|"; reference:url,www.microsoft.com/technet/security/bulletin/ms04-007.asp; reference:url,doc.emergingthreats.net/bin/view/Main/2000017; classtype:bad-unknown; sid:2000017; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NII Microsoft ASN.1 Library Buffer Overflow Exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.microsoft.com/technet/security/bulletin/ms04-007.asp|url,doc.emergingthreats.net/bin/view/Main/2000017

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000032
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS LSA exploit"; flow: to_server,established; content:"|313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131|"; offset: 78; depth: 192; reference:url,www.eeye.com/html/research/advisories/AD20040501.html; reference:url,www.upenn.edu/computing/virus/04/w32.sasser.worm.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000032; classtype:misc-activity; sid:2000032; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **LSA exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.eeye.com/html/research/advisories/AD20040501.html|url,www.upenn.edu/computing/virus/04/w32.sasser.worm.html|url,doc.emergingthreats.net/bin/view/Main/2000032

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011526
`#alert tcp any any -> $HOME_NET [139,445] (msg:"ET NETBIOS windows recycler request - suspicious"; flow:to_server,established; content:"|00 00 5C 00 72 00 65 00 63 00 79 00 63 00 6C 00 65 00 72 00 5C|"; reference:url,about-threats.trendmicro.com/ArchiveMalware.aspx?name=WORM_AUTORUN.ZBC; reference:url,www.symantec.com/connect/forums/virus-alert-crecyclers-1-5-21-1482476501-1644491937-682003330-1013svchostexe; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FFakerecy.A; reference:url,support.microsoft.com/kb/971029; classtype:suspicious-filename-detect; sid:2011526; rev:1; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **windows recycler request - suspicious** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : url,about-threats.trendmicro.com/ArchiveMalware.aspx?name=WORM_AUTORUN.ZBC|url,www.symantec.com/connect/forums/virus-alert-crecyclers-1-5-21-1482476501-1644491937-682003330-1013svchostexe|url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FFakerecy.A|url,support.microsoft.com/kb/971029

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 1

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001944
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS MS04-007 Kill-Bill ASN1 exploit attempt"; flow: established,to_server; content:"CCCC|20f0fd7f|SVWf"; reference:url,www.phreedom.org/solar/exploits/msasn1-bitstring/; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; reference:cve,CAN-2003-0818; reference:url,doc.emergingthreats.net/bin/view/Main/2001944; classtype:attempted-admin; sid:2001944; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MS04-007 Kill-Bill ASN1 exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.phreedom.org/solar/exploits/msasn1-bitstring/|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx|cve,CAN-2003-0818|url,doc.emergingthreats.net/bin/view/Main/2001944

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011527
`#alert tcp any any -> $HOME_NET [139,445] (msg:"ET NETBIOS windows recycler .exe request - suspicious"; flow:to_server,established; content:"|00 00 5C 00 72 00 65 00 63 00 79 00 63 00 6C 00 65 00 72 00 5C|"; content:"|00 2E 00 65 00 78 00 65|"; distance:0; reference:url,about-threats.trendmicro.com/ArchiveMalware.aspx?name=WORM_AUTORUN.ZBC; reference:url,www.symantec.com/connect/forums/virus-alert-crecyclers-1-5-21-1482476501-1644491937-682003330-1013svchostexe; classtype:suspicious-filename-detect; sid:2011527; rev:4; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **windows recycler .exe request - suspicious** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : url,about-threats.trendmicro.com/ArchiveMalware.aspx?name=WORM_AUTORUN.ZBC|url,www.symantec.com/connect/forums/virus-alert-crecyclers-1-5-21-1482476501-1644491937-682003330-1013svchostexe

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012084
`alert tcp $EXTERNAL_NET 445 -> $HOME_NET any (msg:"ET NETBIOS Microsoft Windows SMB Client Race Condition Remote Code Execution"; flow:to_client,established; content:"|ff 53 4d 42 72|"; offset:4; depth:5; content:"|00 00 00 00|"; distance:0; within:4; byte_test:4,<,4356,30,relative,little; reference:url,www.exploit-db.com/exploits/12258/; reference:cve,2010-0017; reference:bid,38100; reference:url,www.microsoft.com/technet/security/Bulletin/MS10-006.mspx; classtype:attempted-user; sid:2012084; rev:2; metadata:created_at 2010_12_22, updated_at 2010_12_22;)
` 

Name : **Microsoft Windows SMB Client Race Condition Remote Code Execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.exploit-db.com/exploits/12258/|cve,2010-0017|bid,38100|url,www.microsoft.com/technet/security/Bulletin/MS10-006.mspx

CVE reference : Not defined

Creation date : 2010-12-22

Last modified date : 2010-12-22

Rev version : 2

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012094
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET NETBIOS SMB Trans2 Query_Fs_Attribute_Info SrvSmbQueryFsInformation Pool Buffer Overflow"; flow:to_server,established; content:"|ff 53 4d 42 32|"; offset:4; depth:5; content:"|00 00 00 00|"; distance:0; within:4; content:"|00 00|"; distance:30; within:2; content:"|00 03 00|"; distance:19; within:3; reference:url,www.exploit-db.com/exploits/14607/; reference:url,seclists.org/fulldisclosure/2010/Aug/122; reference:cve,2010-2550; reference:bid,42224; reference:url,www.microsoft.com/technet/security/Bulletin/MS10-054.mspx; classtype:attempted-user; sid:2012094; rev:2; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **SMB Trans2 Query_Fs_Attribute_Info SrvSmbQueryFsInformation Pool Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.exploit-db.com/exploits/14607/|url,seclists.org/fulldisclosure/2010/Aug/122|cve,2010-2550|bid,42224|url,www.microsoft.com/technet/security/Bulletin/MS10-054.mspx

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 2

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012317
`alert udp $EXTERNAL_NET any -> $HOME_NET [137,138,139,445] (msg:"ET NETBIOS Microsoft Windows Server 2003 Active Directory Pre-Auth BROWSER ELECTION Heap Overflow Attempt"; content:"|42 4F 00|"; content:"BROWSER"; nocase; distance:0; content:"|08 09 A8 0F 01 20|"; fast_pattern; distance:0; isdataat:65,relative; content:!"|0A|"; within:65; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=22457; reference:bid,46360; classtype:attempted-admin; sid:2012317; rev:2; metadata:created_at 2011_02_17, updated_at 2011_02_17;)
` 

Name : **Microsoft Windows Server 2003 Active Directory Pre-Auth BROWSER ELECTION Heap Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,tools.cisco.com/security/center/viewAlert.x?alertId=22457|bid,46360

CVE reference : Not defined

Creation date : 2011-02-17

Last modified date : 2011-02-17

Rev version : 2

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102480
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown unicode attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102480; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102481
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown unicode little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102481; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102482
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102482; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102483
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102483; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102479
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102479; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102478
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102478; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102477
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|w|00|i|00|n|00|r|00|e|00|g|00 00 00|"; within:16; distance:78; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102477; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102476
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|winreg|00|"; within:8; distance:78; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102476; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102472
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS C$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"C|00 24 00 00 00|"; distance:2; nocase; content:!"I|00|P|00|C|00 24 00 00 00|"; within:10; distance:-10; nocase; classtype:protocol-command-decode; sid:2102472; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS C$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102473
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ADMIN$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"A|00|D|00|M|00|I|00|N|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102473; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ADMIN$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102470
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB C$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"C|00 24 00 00 00|"; distance:2; nocase; content:!"I|00|P|00|C|00 24 00 00 00|"; within:10; distance:-10; nocase; classtype:protocol-command-decode; sid:2102470; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB C$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102467
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB D$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"D|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102467; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB D$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102474
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ADMIN$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"ADMIN|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102474; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ADMIN$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102475
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ADMIN$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"A|00|D|00|M|00|I|00|N|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102475; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ADMIN$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102471
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS C$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"C|24 00|"; distance:2; nocase; content:!"IPC|24 00|"; within:5; distance:-5; nocase; classtype:protocol-command-decode; sid:2102471; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS C$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103425
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103425; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103426
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile little endian attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103426; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103177
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103177; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103176
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103176; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103427
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103427; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103428
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode little endian attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103428; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103179
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103179; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103178
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103178; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103377
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103377; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103378
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103378; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103379
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103379; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103380
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103380; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103393
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103393; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103396
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103396; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102942
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102942; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102943
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102943; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102944
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown unicode attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102944; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102945
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown unicode little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102945; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103256
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103256; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103257
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103257; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103258
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning unicode attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103258; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103259
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning unicode little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103259; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102946
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102946; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102936
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102936; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102947
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102947; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102937
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102937; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103018
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; pcre:"/^.{27}/R"; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; pcre:"/^.{4}/R"; byte_test:4,>,1024,36,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103018; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103020
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; pcre:"/^.{27}/R"; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; pcre:"/^.{4}/R"; byte_test:4,>,1024,36,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103020; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103219
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,1024,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103219; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103218
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,1024,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; reference:url,www.microsoft.com/technet/security/bulletin/MS00-040.mspx; classtype:attempted-admin; sid:2103218; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377|url,www.microsoft.com/technet/security/bulletin/MS00-040.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103221
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,2048,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103221; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103220
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,2048,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103220; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103409
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103409; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103410
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation little endian attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103410; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103411
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation unicode attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103411; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103412
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation unicode little endian attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103412; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103240
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103240; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103241
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103241; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103115
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103115; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103114
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103114; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103117
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103117; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103116
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103116; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103098
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103098; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103090
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|llsrpc|00|"; within:8; distance:78; nocase; classtype:protocol-command-decode; sid:2103090; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103099
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103099; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103160
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103160; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103161
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103161; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102932
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102932; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103162
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103162; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103163
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103163; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102928
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|nddeapi|00|"; within:9; distance:78; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102928; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102933
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi unicode bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102933; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102929
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|n|00|d|00|d|00|e|00|a|00|p|00|i|00 00 00|"; within:18; distance:78; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102929; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103202
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103202; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102940
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102940; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102174
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|winreg|00|"; within:8; distance:78; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102174; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103203
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103203; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103204
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103204; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102941
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102941; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102175
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|w|00|i|00|n|00|r|00|e|00|g|00 00 00|"; within:16; distance:78; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102175; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103205
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103205; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103433
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103433; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103434
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile little endian attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103434; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103185
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103185; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103184
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103184; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103435
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103435; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103436
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode little endian attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103436; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103187
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103187; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103186
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103186; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102468
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS D$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"D|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102468; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS D$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102469
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS D$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"D|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102469; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS D$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103385
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103385; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103386
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103386; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103387
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103387; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103388
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103388; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102465
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IPC$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"IPC|24 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2102465; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IPC$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102466
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IPC$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"I|00|P|00|C|00 24 00 00 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2102466; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IPC$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103401
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103401; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103402
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103402; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103403
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103403; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103404
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103404; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103264
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103264; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103265
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103265; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103266
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning unicode attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103266; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103267
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning unicode little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103267; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102948
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102948; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102939
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102939; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103024
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; pcre:"/^.{27}/R"; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; pcre:"/^.{4}/R"; byte_test:4,>,1024,36,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103024; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103227
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,1024,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103227; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103226
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,1024,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103226; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103229
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,2048,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103229; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103228
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,2048,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103228; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103417
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103417; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103418
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation little endian attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103418; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103419
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation unicode attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103419; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103420
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation unicode little endian attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103420; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation unicode little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103248
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103248; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103249
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103249; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103250
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103250; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103251
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103251; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103123
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103123; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103122
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103122; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103125
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103125; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103124
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect unicode overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103124; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect unicode overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103106
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103106; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103094
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|llsrpc|00|"; within:8; distance:78; nocase; classtype:protocol-command-decode; sid:2103094; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103107
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103107; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103108
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103108; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103095
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|l|00|l|00|s|00|r|00|p|00|c|00 00 00|"; within:16; distance:78; nocase; classtype:protocol-command-decode; sid:2103095; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103109
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103109; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103170
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103170; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103171
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103171; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102934
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102934; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102930
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|5C|nddeapi|00|"; within:9; distance:78; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102930; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102935
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi unicode bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102935; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102931
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|n|00|d|00|d|00|e|00|a|00|p|00|i|00 00 00|"; within:18; distance:78; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102931; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103210
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103210; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103211
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103211; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103212
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103212; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103213
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103213; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103394
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103394; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103395
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103395; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103242
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103242; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103243
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103243; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103100
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103100; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103091
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB|A2|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|5C 00|l|00|l|00|s|00|r|00|p|00|c|00 00 00|"; within:16; distance:78; nocase;  classtype:protocol-command-decode; sid:2103091; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103101
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103101; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102938
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102938; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102949
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW unicode little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102949; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW unicode little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103168
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103168; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103169
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue little endian bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103169; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100538
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IPC$ unicode share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_jump:2,34,little,relative; content:"I|00|P|00|C|00 24 00 00 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2100538; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IPC$ unicode share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100537
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IPC$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"IPC|24 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2100537; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IPC$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100536
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB D$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"D|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2100536; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB D$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100535
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CD..."; flow:to_server,established; content:"|5C|...|00 00 00|"; reference:arachnids,337; classtype:attempted-recon; sid:2100535; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CD...** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,337

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100534
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CD.."; flow:to_server,established; content:"|5C|../|00 00 00|"; reference:arachnids,338; classtype:attempted-recon; sid:2100534; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CD..** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,338

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100533
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB C$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"C|24 00|"; distance:2; nocase; content:!"IPC|24 00|"; within:5; distance:-5; nocase; classtype:protocol-command-decode; sid:2100533; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB C$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100532
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ADMIN$ share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_jump:2,34,little,relative; content:"ADMIN|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2100532; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ADMIN$ share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100530
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS NT NULL session"; flow:to_server,established; content:"|00 00 00 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00| |00|N|00|T|00| |00|1|00|3|00|8|00|1"; reference:arachnids,204; reference:bugtraq,1163; reference:cve,2000-0347; classtype:attempted-recon; sid:2100530; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NT NULL session** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,204|bugtraq,1163|cve,2000-0347

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100529
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS DOS RFPoison"; flow:to_server,established; content:"|5C 00 5C 00|*|00|S|00|M|00|B|00|S|00|E|00|R|00|V|00|E|00|R|00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00|"; reference:arachnids,454; classtype:attempted-dos; sid:2100529; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DOS RFPoison** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : arachnids,454

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102382
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup NTMLSSP asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,!&,128,6,relative; pcre:"/^.{27}/R"; byte_test:4,&,2147483648,21,relative,little; content:!"NTLMSSP"; within:7; distance:27; asn1:double_overflow, bitstring_overflow, relative_offset 27, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2102382; rev:22; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup NTMLSSP asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 22

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102383
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_test:4,&,2147483648,48,relative,little; content:!"NTLMSSP"; within:7; distance:54; asn1:double_overflow, bitstring_overflow, relative_offset 54, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2102383; rev:21; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup NTMLSSP asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 21

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103003
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_test:4,&,2147483648,48,relative,little; content:!"NTLMSSP"; within:7; distance:54; asn1:double_overflow, bitstring_overflow, relative_offset 54, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103003; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102403
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup AndX request unicode username overflow attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,&,128,6,relative; pcre:"/^.{27}/sR"; byte_test:4,!&,2147483648,21,relative,little; content:!"|00 00|"; within:510; distance:29; reference:bugtraq,9752; reference:url,www.eeye.com/html/Research/Advisories/AD20040226.html; classtype:protocol-command-decode; sid:2102403; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup AndX request unicode username overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9752|url,www.eeye.com/html/Research/Advisories/AD20040226.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102404
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup AndX request unicode username overflow attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"s"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_test:4,!&,2147483648,21,relative,little; content:!"|00 00|"; within:510; distance:29; reference:bugtraq,9752; reference:url,www.eeye.com/html/Research/Advisories/AD20040226.html; classtype:protocol-command-decode; sid:2102404; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup AndX request unicode username overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9752|url,www.eeye.com/html/Research/Advisories/AD20040226.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103437
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103437; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103429
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103429; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103158
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC CoGetInstanceFromFile little endian overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|05|"; depth:1; byte_test:1,&,16,3,relative; content:"|00|"; offset:1;depth:1;  content:"|01 00|";distance:19; within:2; byte_test:4,>,128,20,relative,little; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103158; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC CoGetInstanceFromFile little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103159
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC CoGetInstanceFromFile overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103159; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC CoGetInstanceFromFile overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103275
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC IActivation bind attempt"; flow:established,to_server; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; classtype:protocol-command-decode; sid:2103275; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC IActivation bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103276
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC IActivation little endian bind attempt"; flow:established,to_server; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; classtype:protocol-command-decode; sid:2103276; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC IActivation little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103198
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC ISystemActivator path overflow attempt big endian"; flow:to_server,established; content:"|05|"; byte_test:1,<,16,3,relative; content:"|5C 00 5C 00|"; byte_test:4,>,256,-8,relative; flowbits:isset,dce.isystemactivator.bind; reference:bugtraq,8205; reference:cve,2003-0352; reference:nessus,11808; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103198; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC ISystemActivator path overflow attempt big endian** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8205|cve,2003-0352|nessus,11808|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103197
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC ISystemActivator path overflow attempt little endian"; flow:to_server,established; content:"|05|"; byte_test:1,&,16,3,relative; content:"|5C 5C|"; byte_test:4,>,256,-8,little,relative; flowbits:isset,dce.isystemactivator.bind; reference:bugtraq,8205; reference:cve,2003-0352; reference:nessus,11808; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103197; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC ISystemActivator path overflow attempt little endian** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8205|cve,2003-0352|nessus,11808|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103238
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC IrotIsRunning attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_test:4,>,128,0,relative; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103238; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC IrotIsRunning attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103239
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC IrotIsRunning little endian attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_test:4,>,128,0,little,relative; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103239; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC IrotIsRunning little endian attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103236
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC irot bind attempt"; flow:established,to_server; content:"|05|"; depth:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103236; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC irot bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103237
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC irot little endian bind attempt"; flow:established,to_server; content:"|05|"; depth:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103237; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC irot little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103156
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC msqueue bind attempt"; flow:to_server,established; content:"|05|"; depth:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103156; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC msqueue bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103157
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC msqueue little endian bind attempt"; flow:to_server,established; content:"|05|"; depth:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103157; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC msqueue little endian bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103195
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 137 (msg:"GPL NETBIOS name query overflow attempt TCP"; flow:to_server,established; byte_test:1,&,64,2; content:" "; offset:12; isdataat:56,relative; metadata: former_category NETBIOS; reference:bugtraq,9624; reference:cve,2003-0825; classtype:attempted-admin; sid:2103195; rev:5; metadata:created_at 2010_09_23, updated_at 2017_11_10;)
` 

Name : **name query overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9624|cve,2003-0825

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2017-11-10

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103180
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103180; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103430
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103430; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103181
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103181; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103431
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103431; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103182
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103182; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103432
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103432; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103381
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103381; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103382
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103382; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103383
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103383; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103384
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IActivation unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103384; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IActivation unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103397
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103397; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103398
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103398; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103399
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103399; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103400
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB ISystemActivator unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103400; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB ISystemActivator unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103260
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103260; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103261
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103261; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103262
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning unicode andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103262; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103263
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB IrotIsRunning unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103263; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB IrotIsRunning unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103022
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; pcre:"/^.{27}/R"; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; isdataat:4,relative; byte_test:4,>,1024,40,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103022; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103019
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE andx oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; byte_test:4,>,1024,40,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103019; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE andx oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103034
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103034; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103026
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103026; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103035
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE andx DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103035; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE andx DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103027
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE andx SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103027; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE andx SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103051
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103051; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103042
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103042; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103050
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103050; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103036
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103036; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103028
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103028; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103037
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode andx DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103037; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode andx DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103029
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode andx SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103029; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode andx SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103045
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; isdataat:4,relative; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103045; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103053
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; isdataat:4,relative; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103053; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103044
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103044; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103052
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103052; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103038
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103038; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103030
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103030; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103039
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE andx DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103039; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE andx DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103031
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE andx SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103031; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE andx SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103047
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103047; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103055
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103055; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103046
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103046; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103054
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,!&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103054; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103040
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103040; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103032
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103032; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103041
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode andx DACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103041; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode andx DACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103033
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode andx SACL overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; byte_test:4,>,32,-16,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103033; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode andx SACL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103049
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103049; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103057
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103057; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103048
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103048; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103056
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"|01 00|"; within:2; distance:64; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:20; byte_jump:4,20,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103056; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103222
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,1024,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103222; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103223
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,1024,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103223; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103224
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,2048,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103224; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103225
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB OpenKey unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,2048,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103225; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB OpenKey unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103413
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103413; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103414
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103414; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103415
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation unicode andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103415; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103416
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB RemoteActivation unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103416; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB RemoteActivation unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103001
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup NTMLSSP andx asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"s"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_test:4,&,2147483648,21,relative,little; content:!"NTLMSSP"; within:7; distance:27; asn1:double_overflow, bitstring_overflow, relative_offset 27, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103001; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup NTMLSSP andx asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103002
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup NTMLSSP unicode andx asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"s"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_test:4,&,2147483648,21,relative,little; content:!"NTLMSSP"; within:7; distance:27; asn1:double_overflow, bitstring_overflow, relative_offset 27, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103002; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup NTMLSSP unicode andx asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103244
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103244; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103245
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103245; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103246
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103246; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103247
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103247; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB irot unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103118
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103118; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103119
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103119; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103120
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103120; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103121
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103121; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrconnect unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103102
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103102; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103092
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|llsrpc|00|"; within:8; distance:51; nocase; classtype:protocol-command-decode; sid:2103092; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103103
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103103; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103104
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103104; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103093
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|l|00|l|00|s|00|r|00|p|00|c|00 00 00|"; within:16; distance:51; nocase; classtype:protocol-command-decode; sid:2103093; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103105
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrpc unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103105; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB llsrpc unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103164
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103164; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103165
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103165; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103166
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103166; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103167
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103167; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB msqueue unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103206
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103206; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103207
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103207; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103208
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103208; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103209
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103209; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103188
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103188; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103438
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103438; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103189
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,128,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103189; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103439
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 04|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103439; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103190
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 01|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103190; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103440
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.isystemactivator.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|04 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103440; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103191
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS CoGetInstanceFromFile unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103191; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS CoGetInstanceFromFile unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103389
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103389; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103390
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103390; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103391
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103391; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103392
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IActivation unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; flowbits:set,dce.iactivation.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103392; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IActivation unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103405
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103405; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103406
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103406; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103407
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103407; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103408
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ISystemActivator unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2103408; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ISystemActivator unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103268
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103268; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103269
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103269; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103270
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning unicode andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 02|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103270; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103271
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|02 00|"; within:2; distance:19; byte_jump:4,8,relative,little,align; byte_test:4,>,1024,0,little; reference:bugtraq,6005; reference:cve,2002-1561; reference:url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx; classtype:protocol-command-decode; sid:2103271; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IrotIsRunning unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,6005|cve,2002-1561|url,www.microsoft.com/technet/security/bulletin/MS03-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103023
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE andx oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; byte_test:4,>,1024,40,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103023; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE andx oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103025
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NT Trans NT CREATE unicode andx oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; byte_test:4,>,1024,40,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103025; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NT Trans NT CREATE unicode andx oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103230
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,1024,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103230; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103231
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,1024,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103231; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103232
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0F|"; within:2; distance:19; byte_test:2,>,2048,20,relative; reference:bugtraq,1331; reference:cve,2000-0377; classtype:attempted-admin; sid:2103232; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103233
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS OpenKey unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0F 00|"; within:2; distance:19; byte_test:2,>,2048,20,relative,little; reference:bugtraq,1331; reference:cve,2000-0377; reference:url,www.microsoft.com/technet/security/bulletin/MS00-040.mspx; classtype:attempted-admin; sid:2103233; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS OpenKey unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1331|cve,2000-0377|url,www.microsoft.com/technet/security/bulletin/MS00-040.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103421
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6; classtype:protocol-command-decode; sid:2103421; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103422
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 5C|"; byte_test:4,>,256,6,little; classtype:protocol-command-decode; sid:2103422; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103423
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation unicode andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8; classtype:protocol-command-decode; sid:2103423; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103424
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS RemoteActivation unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,dce.iactivation.bind; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; content:"|5C 00 5C 00|"; byte_test:4,>,256,8,little; classtype:protocol-command-decode; sid:2103424; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS RemoteActivation unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103004
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup NTMLSSP andx asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"s"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_test:4,&,2147483648,21,relative,little; content:!"NTLMSSP"; within:7; distance:27; asn1:double_overflow, bitstring_overflow, relative_offset 27, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103004; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup NTMLSSP andx asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103005
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode andx asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"s"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_test:4,&,2147483648,21,relative,little; content:!"NTLMSSP"; within:7; distance:27; asn1:double_overflow, bitstring_overflow, relative_offset 27, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103005; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup NTMLSSP unicode andx asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103142
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 andx attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:29; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103142; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 FIND_FIRST2 andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103252
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103252; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103253
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103253; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103254
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103254; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103255
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS irot unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; flowbits:set,smb.tree.bind.irot; flowbits:noalert; classtype:protocol-command-decode; sid:2103255; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS irot unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103126
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103126; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103127
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,52,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103127; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103128
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103128; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103129
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrconnect unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 00|"; within:2; distance:19; byte_test:4,>,104,0,relative; reference:url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx; classtype:attempted-admin; sid:2103129; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrconnect unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.microsoft.com/technet/security/bulletin/ms05-010.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103110
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103110; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103096
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|llsrpc|00|"; within:8; distance:51; nocase; classtype:protocol-command-decode; sid:2103096; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103111
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103111; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103112
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103112; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103097
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|l|00|l|00|s|00|r|00|p|00|c|00 00 00|"; within:16; distance:51; nocase; classtype:protocol-command-decode; sid:2103097; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103113
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS llsrpc unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"@|FD|,4l<|CE 11 A8 93 08 00|+.|9C|m"; within:16; distance:29; flowbits:set,smb.tree.bind.llsrpc; classtype:protocol-command-decode; sid:2103113; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS llsrpc unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103172
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103172; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103173
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103173; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103174
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103174; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103175
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS msqueue unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|B0 01|R|97 CA|Y|D0 11 A8 D5 00 A0 C9 0D 80|Q"; within:16; distance:29; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2103175; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS msqueue unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103214
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103214; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103215
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103215; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103216
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103216; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103217
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode little endian andx bind attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; flowbits:noalert; classtype:protocol-command-decode; sid:2103217; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode little endian andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103196
`#alert udp $EXTERNAL_NET any -> $HOME_NET 137 (msg:"GPL NETBIOS name query overflow attempt UDP"; byte_test:1,&,64,2; content:" "; offset:12; isdataat:56,relative; reference:bugtraq,9624; reference:cve,2003-0825; classtype:attempted-admin; sid:2103196; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **name query overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9624|cve,2003-0825

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103200
`#alert udp $EXTERNAL_NET any -> $HOME_NET 42 (msg:"GPL NETBIOS WINS name query overflow attempt UDP"; byte_test:1,&,64,2; content:" "; offset:12; isdataat:56,relative; reference:bugtraq,9624; reference:cve,2003-0825; reference:url,www.microsoft.com/technet/security/bulletin/MS04-006.mspx; classtype:attempted-admin; sid:2103200; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **WINS name query overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9624|cve,2003-0825|url,www.microsoft.com/technet/security/bulletin/MS04-006.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103235
`#alert udp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS Messenger message overflow attempt"; content:"|04 00|"; depth:2; byte_test:1,!&,16,2,relative; content:"|F8 91|{Z|00 FF D0 11 A9 B2 00 C0|O|B6 E6 FC|"; within:16; distance:22; content:"|00 00|"; within:2; distance:28; byte_jump:4,18,align,relative; byte_jump:4,8,align,relative; byte_test:4,>,1024,8,relative; reference:bugtraq,8826; reference:cve,2003-0717; classtype:attempted-admin; sid:2103235; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Messenger message overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8826|cve,2003-0717

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103234
`#alert udp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS Messenger message little endian overflow attempt"; content:"|04 00|"; depth:2; byte_test:1,&,16,2,relative; content:"|F8 91|{Z|00 FF D0 11 A9 B2 00 C0|O|B6 E6 FC|"; within:16; distance:22; content:"|00 00|"; within:2; distance:28; byte_jump:4,18,little,align,relative; byte_jump:4,8,little,align,relative; byte_test:4,>,1024,8,little,relative; reference:bugtraq,8826; reference:cve,2003-0717; classtype:attempted-admin; sid:2103234; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Messenger message little endian overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8826|cve,2003-0717

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102349
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC enumerate printers request attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; fast_pattern; within:12; distance:5; nocase; content:"|05|"; distance:1; content:"|00|"; within:1; distance:1; byte_test:1,&,3,0,relative; content:"|00 00|"; within:2; distance:19; flowbits:isset,dce.printer.bind; classtype:attempted-recon; sid:2102349; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC enumerate printers request attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102348
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC print spool bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00 05 00 0B|"; within:17; distance:5; byte_test:1,&,16,1,relative; content:"xV4|12|4|12 CD AB EF 00 01 23|Eg|89 AB|"; within:16; distance:29; flowbits:set,dce.printer.bind; flowbits:noalert; classtype:protocol-command-decode; sid:2102348; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC print spool bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102316
`alert udp $EXTERNAL_NET any -> $HOME_NET 1024: (msg:"GPL NETBIOS DCERPC Workstation Service direct service access attempt"; content:"|04 00|"; depth:2; byte_test:1,&,16,2,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:22; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102316; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC Workstation Service direct service access attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102315
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1024: (msg:"GPL NETBIOS DCERPC Workstation Service direct service bind attempt"; flow:to_server,established; content:"|05 00 0B|"; depth:3; byte_test:1,&,16,1,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:29; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102315; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC Workstation Service direct service bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102311
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC Workstation Service bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00 0B|"; within:10; distance:4; byte_test:1,&,16,1,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:29; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102311; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC Workstation Service bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102310
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC Workstation Service unicode bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,&,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 05 00 0B|"; within:15; distance:4; byte_test:1,&,16,1,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:29; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102310; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC Workstation Service unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102309
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC Workstation Service bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00 0B|"; within:10; distance:4; byte_test:1,&,16,1,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:29; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102309; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC Workstation Service bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102308
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC Workstation Service unicode bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,&,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 05 00 0B|"; within:15; distance:4; byte_test:1,&,16,1,relative; content:"|98 D0 FF|k|12 A1 10|6|98|3F|C3 F8|~4Z"; within:16; distance:29; reference:bugtraq,9011; reference:cve,2003-0812; reference:url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx; classtype:misc-attack; sid:2102308; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC Workstation Service unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9011|cve,2003-0812|url,www.microsoft.com/technet/security/bulletin/MS03-049.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102258
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC Messenger Service buffer overflow attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|04 00|"; within:2; byte_test:1,>,15,2,relative; byte_jump:4,86,little,align,relative; byte_jump:4,8,little,align,relative; byte_test:4,>,1024,0,little,relative; reference:bugtraq,8826; reference:cve,2003-0717; reference:nessus,11888; reference:nessus,11890; reference:url,www.microsoft.com/technet/security/bulletin/MS03-043.mspx; classtype:attempted-admin; sid:2102258; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC Messenger Service buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8826|cve,2003-0717|nessus,11888|nessus,11890|url,www.microsoft.com/technet/security/bulletin/MS03-043.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102257
`alert udp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC Messenger Service buffer overflow attempt"; content:"|04 00|"; depth:2; byte_test:1,>,15,2,relative; byte_jump:4,86,little,align,relative; byte_jump:4,8,little,align,relative; byte_test:4,>,1024,0,little,relative; reference:bugtraq,8826; reference:cve,2003-0717; reference:nessus,11888; reference:nessus,11890; reference:url,www.microsoft.com/technet/security/bulletin/MS03-043.mspx; classtype:attempted-admin; sid:2102257; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC Messenger Service buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8826|cve,2003-0717|nessus,11888|nessus,11890|url,www.microsoft.com/technet/security/bulletin/MS03-043.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102252
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC Remote Activation bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; tag:session,5,packets; reference:bugtraq,8234; reference:bugtraq,8458; reference:cve,2003-0528; reference:cve,2003-0605; reference:cve,2003-0715; reference:nessus,11798; reference:nessus,11835; reference:url,www.microsoft.com/technet/security/bulletin/MS03-039.mspx; classtype:attempted-admin; sid:2102252; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC Remote Activation bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8234|bugtraq,8458|cve,2003-0528|cve,2003-0605|cve,2003-0715|nessus,11798|nessus,11835|url,www.microsoft.com/technet/security/bulletin/MS03-039.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102251
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC Remote Activation bind attempt"; flow:to_server,established; content:"|05|"; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|B8|J|9F|M|1C|}|CF 11 86 1E 00| |AF|n|7C|W"; within:16; distance:29; tag:session,5,packets; reference:bugtraq,8234; reference:bugtraq,8458; reference:cve,2003-0528; reference:cve,2003-0605; reference:cve,2003-0715; reference:nessus,11798; reference:nessus,11835; reference:url,www.microsoft.com/technet/security/bulletin/MS03-039.mspx; classtype:attempted-admin; sid:2102251; rev:16; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC Remote Activation bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8234|bugtraq,8458|cve,2003-0528|cve,2003-0605|cve,2003-0715|nessus,11798|nessus,11835|url,www.microsoft.com/technet/security/bulletin/MS03-039.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 16

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102193
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC ISystemActivator bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind.call.attempt; reference:bugtraq,8205; reference:cve,2003-0352; reference:nessus,11808; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2102193; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC ISystemActivator bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,8205|cve,2003-0352|nessus,11808|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102192
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC ISystemActivator bind attempt"; flow:to_server,established; content:"|05|"; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind.attempt; flowbits:noalert; reference:bugtraq,8205; reference:cve,2003-0352; reference:nessus,11808; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:protocol-command-decode; sid:2102192; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC ISystemActivator bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,8205|cve,2003-0352|nessus,11808|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102191
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB DCERPC invalid bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; distance:2; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|00|"; within:1; distance:21; classtype:attempted-dos; sid:2102191; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC invalid bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102190
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC invalid bind attempt"; flow:to_server,established; content:"|05|"; depth:1; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|00|"; within:1; distance:21; classtype:attempted-dos; sid:2102190; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC invalid bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102177
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB startup folder unicode access"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB2"; depth:5; offset:4; content:"|5C 00|S|00|t|00|a|00|r|00|t|00| |00|M|00|e|00|n|00|u|00 5C 00|P|00|r|00|o|00|g|00|r|00|a|00|m|00|s|00 5C 00|S|00|t|00|a|00|r|00|t|00|u|00|p"; distance:0; nocase; classtype:attempted-recon; sid:2102177; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB startup folder unicode access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102176
`alert tcp any any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB startup folder access"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB2"; depth:5; offset:4; content:"Documents and Settings|5C|All Users|5C|Start Menu|5C|Programs|5C|Startup|00|"; distance:0; nocase; classtype:attempted-recon; sid:2102176; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB startup folder access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102103
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB trans2open buffer overflow attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB2"; depth:5; offset:4; content:"|00 14|"; depth:2; offset:60; byte_test:2,>,256,0,relative,little; reference:bugtraq,7294; reference:cve,2003-0201; reference:url,www.digitaldefense.net/labs/advisories/DDI-1013.txt; classtype:attempted-admin; sid:2102103; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB trans2open buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,7294|cve,2003-0201|url,www.digitaldefense.net/labs/advisories/DDI-1013.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102102
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB SMB_COM_TRANSACTION Max Data Count of 0 DOS Attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; content:"|00 00|"; depth:2; offset:45; reference:bugtraq,5556; reference:cve,2002-0724; reference:url,www.corest.com/common/showdoc.php?idx=262; reference:url,www.microsoft.com/technet/security/bulletin/MS02-045.mspx; reference:nessus,11110; classtype:denial-of-service; sid:2102102; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB SMB_COM_TRANSACTION Max Data Count of 0 DOS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,5556|cve,2002-0724|url,www.corest.com/common/showdoc.php?idx=262|url,www.microsoft.com/technet/security/bulletin/MS02-045.mspx|nessus,11110

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102101
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB SMB_COM_TRANSACTION Max Parameter and Max Count of 0 DOS Attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; content:"|00 00 00 00|"; depth:4; offset:43; reference:bugtraq,5556; reference:cve,2002-0724; reference:nessus,11110; reference:url,www.corest.com/common/showdoc.php?idx=262; reference:url,www.microsoft.com/technet/security/bulletin/MS02-045.mspx; classtype:denial-of-service; sid:2102101; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB SMB_COM_TRANSACTION Max Parameter and Max Count of 0 DOS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,5556|cve,2002-0724|nessus,11110|url,www.corest.com/common/showdoc.php?idx=262|url,www.microsoft.com/technet/security/bulletin/MS02-045.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102507
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC LSASS bind attempt"; flow:to_server,established; content:"|05|"; depth:1; content:"|00|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102507; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC LSASS bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102508
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC LSASS DsRolerUpgradeDownlevelServer Exploit attempt"; flow:to_server,established; content:"|05|"; content:"|00|"; within:1; distance:1; content:"|09 00|"; within:2; distance:19; flowbits:isset,netbios.lsass.bind.attempt; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-admin; sid:2102508; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC LSASS DsRolerUpgradeDownlevelServer Exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102509
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC LSASS unicode bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,&,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 05 00 0B|"; within:15; distance:4; byte_test:1,&,16,1,relative; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102509; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC LSASS unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102510
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC LSASS bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,^,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C|PIPE|5C 00 05 00 0B|"; within:10; distance:4; byte_test:1,&,16,1,relative; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102510; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC LSASS bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102511
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC LSASS DsRolerUpgradeDownlevelServer exploit attempt"; flow:to_server,established; flowbits:isset,netbios.lsass.bind.attempt; content:"|FF|SMB"; depth:4; offset:4; nocase; content:"|05|"; distance:59; content:"|00|"; within:1; distance:1; content:"|09 00|"; within:2; distance:19; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-admin; sid:2102511; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC LSASS DsRolerUpgradeDownlevelServer exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102512
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC LSASS bind attempt"; flow:to_server,established; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00|"; within:12; distance:5; nocase; content:"|05|"; within:1; distance:2; content:"|0B|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102512; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC LSASS bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102513
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC LSASS unicode bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 05 00 0B|"; within:15; distance:4; byte_test:1,&,16,1,relative; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102513; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC LSASS unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102514
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC LSASS DsRolerUpgradeDownlevelServer exploit attempt"; flow:to_server,established; flowbits:isset,netbios.lsass.bind.attempt; content:"|FF|SMB"; depth:4; offset:4; nocase; content:"|05|"; distance:59; content:"|00|"; within:1; distance:1; content:"|09 00|"; within:2; distance:19; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-admin; sid:2102514; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC LSASS DsRolerUpgradeDownlevelServer exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102524
`alert tcp $EXTERNAL_NET any -> $HOME_NET 135 (msg:"GPL NETBIOS DCERPC LSASS direct bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB"; depth:4; offset:4; nocase; content:"|05|"; content:"|0B|"; within:1; distance:1; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102524; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DCERPC LSASS direct bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102525
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB DCERPC LSASS direct bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB"; depth:4; offset:4; nocase; content:"|05|"; content:"|0B|"; within:1; distance:1; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102525; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB DCERPC LSASS direct bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102526
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC LSASS direct bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB"; depth:4; offset:4; nocase; content:"|05|"; content:"|0B|"; within:1; distance:1; content:"j|28 19|9|0C B1 D0 11 9B A8 00 C0|O|D9|.|F5|"; within:16; distance:29; flowbits:set,netbios.lsass.bind.attempt; flowbits:noalert; reference:bugtraq,10108; reference:cve,2003-0533; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102526; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC LSASS direct bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,10108|cve,2003-0533|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102563
`#alert udp $EXTERNAL_NET 137 -> $HOME_NET any (msg:"GPL NETBIOS NS lookup response name overflow attempt"; byte_test:1,>,127,2; content:"|00 01|"; depth:2; offset:6; byte_test:1,>,32,12; metadata: former_category NETBIOS; reference:bugtraq,10333; reference:bugtraq,10334; reference:cve,2004-0444; reference:cve,2004-0445; reference:url,www.eeye.com/html/Research/Advisories/AD20040512A.html; classtype:attempted-admin; sid:2102563; rev:6; metadata:created_at 2010_09_23, updated_at 2017_08_24;)
` 

Name : **NS lookup response name overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10333|bugtraq,10334|cve,2004-0444|cve,2004-0445|url,www.eeye.com/html/Research/Advisories/AD20040512A.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2017-08-24

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103143
`#alert tcp $HOME_NET 139 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB Trans2 FIND_FIRST2 response overflow attempt"; flow:established,to_client; flowbits:isset,smb.trans2; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; flowbits:unset,smb.trans2; byte_test:2,>,15,34,relative,little; reference:cve,2005-0045; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx; classtype:protocol-command-decode; sid:2103143; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 FIND_FIRST2 response overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2005-0045|url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103144
`#alert tcp $HOME_NET 139 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB Trans2 FIND_FIRST2 response andx overflow attempt"; flow:established,to_client; flowbits:isset,smb.trans2; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; flowbits:unset,smb.trans2; byte_test:2,>,15,7,relative,little; reference:cve,2005-0045; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx; classtype:protocol-command-decode; sid:2103144; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 FIND_FIRST2 response andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2005-0045|url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103145
`#alert tcp $HOME_NET 445 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 response overflow attempt"; flow:established,to_client; flowbits:isset,smb.trans2; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; flowbits:unset,smb.trans2; byte_test:2,>,15,34,relative,little; reference:cve,2005-0045; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx; classtype:protocol-command-decode; sid:2103145; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 FIND_FIRST2 response overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2005-0045|url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103146
`#alert tcp $HOME_NET 445 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 response andx overflow attempt"; flow:established,to_client; flowbits:isset,smb.trans2; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; flowbits:unset,smb.trans2; byte_test:2,>,15,7,relative,little; reference:cve,2005-0045; reference:url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx; classtype:protocol-command-decode; sid:2103146; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 FIND_FIRST2 response andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2005-0045|url,www.microsoft.com/technet/security/Bulletin/MS05-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103135
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Trans2 QUERY_FILE_INFO attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|07 00|"; within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103135; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 QUERY_FILE_INFO attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103136
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Trans2 QUERY_FILE_INFO andx attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|07 00|"; within:2; distance:29; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103136; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 QUERY_FILE_INFO andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103137
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 QUERY_FILE_INFO attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|07 00|"; within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103137; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 QUERY_FILE_INFO attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103138
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 QUERY_FILE_INFO andx attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|07 00|"; within:2; distance:29; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103138; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 QUERY_FILE_INFO andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103139
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Trans2 FIND_FIRST2 attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103139; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 FIND_FIRST2 attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103140
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Trans2 FIND_FIRST2 andx attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; content:"2"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:29; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103140; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Trans2 FIND_FIRST2 andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103141
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Trans2 FIND_FIRST2 attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100292
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS x86 Linux samba overflow"; flow:to_server,established; content:"|EB|/_|EB|J^|89 FB 89|>|89 F2|"; reference:bugtraq,1816; reference:bugtraq,536; reference:cve,1999-0182; reference:cve,1999-0811; classtype:attempted-admin; sid:2100292; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 Linux samba overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1816|bugtraq,536|cve,1999-0182|cve,1999-0811

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100686
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL NETBIOS xp_reg* - registry access"; flow:to_server,established; content:"x|00|p|00|_|00|r|00|e|00|g|00|"; nocase; reference:bugtraq,5205; reference:cve,2002-0642; reference:nessus,10642; reference:url,www.microsoft.com/technet/security/bulletin/MS02-034; classtype:attempted-user; sid:2100686; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xp_reg* - registry access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,5205|cve,2002-0642|nessus,10642|url,www.microsoft.com/technet/security/bulletin/MS02-034

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100689
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL NETBIOS xp_reg* registry access"; flow:to_server,established; content:"x|00|p|00|_|00|r|00|e|00|g|00|"; depth:32; offset:32; nocase; reference:bugtraq,5205; reference:cve,2002-0642; reference:nessus,10642; reference:url,www.microsoft.com/technet/security/bulletin/MS02-034; classtype:attempted-user; sid:2100689; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xp_reg* registry access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,5205|cve,2002-0642|nessus,10642|url,www.microsoft.com/technet/security/bulletin/MS02-034

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103183
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB CoGetInstanceFromFile unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.msqueue; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|01 00|"; within:2; distance:19; byte_test:4,>,256,20,relative; reference:cve,2003-0995; reference:url,www.eeye.com/html/Research/Advisories/AD20030910.html; reference:url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx; classtype:attempted-admin; sid:2103183; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB CoGetInstanceFromFile unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2003-0995|url,www.eeye.com/html/Research/Advisories/AD20030910.html|url,www.microsoft.com/technet/security/bulletin/MS03-026.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103021
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE unicode andx oversized Security Descriptor attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-15,little,relative,from_beginning; isdataat:4,relative; byte_test:4,>,1024,40,relative,little; reference:cve,2004-1154; classtype:protocol-command-decode; sid:2103021; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE unicode andx oversized Security Descriptor attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2004-1154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102999
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; within:1; distance:4; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102999; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102998
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown unicode andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102998; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102997
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102997; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102996
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS InitiateSystemShutdown andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102996; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS InitiateSystemShutdown andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102995
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102995; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown unicode little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102994
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown unicode andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102994; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown unicode andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102993
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|18 00|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102993; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown little endian andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102992
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB InitiateSystemShutdown andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 18|"; within:2; distance:19; classtype:protocol-command-decode; sid:2102992; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB InitiateSystemShutdown andx attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102991
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; content:"|05|"; distance:4; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102991; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102964
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102964; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102965
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102965; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102966
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102966; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102967
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NDdeSetTrustedShareW unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102967; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NDdeSetTrustedShareW unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102384
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NTLMSSP invalid mechlistMIC attempt"; flow:to_server,established; content:"|FF|SMBs"; depth:5; offset:4; nocase; content:"`"; depth:1; offset:63; content:"|00 00 00|b|06 83 00 00 06|+|06 01 05 05 02|"; within:15; distance:1; content:"|06 0A|+|06 01 04 01 82|7|02 02 0A|"; distance:0; content:"|A3|>0<|A0|0"; distance:0; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12054; reference:nessus,12065; classtype:attempted-dos; sid:2102384; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NTLMSSP invalid mechlistMIC attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12054|nessus,12065

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102401
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup AndX request username overflow attempt"; flow:to_server,established; content:"|00|"; depth:1; byte_test:2,>,322,2; content:"|FF|SMBs"; depth:5; offset:4; nocase; byte_test:1,<,128,6,relative; content:"|00 00 00 00|"; within:4; distance:42; byte_test:2,>,255,8,relative,little; content:!"|00|"; within:255; distance:10; reference:bugtraq,9752; reference:url,www.eeye.com/html/Research/Advisories/AD20040226.html; classtype:attempted-admin; sid:2102401; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup AndX request username overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9752|url,www.eeye.com/html/Research/Advisories/AD20040226.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102960
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102960; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102956
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|nddeapi|00|"; within:9; distance:51; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102956; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102961
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi unicode andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102961; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102957
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB nddeapi unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|n|00|d|00|d|00|e|00|a|00|p|00|i|00 00 00|"; within:18; distance:51; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102957; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB nddeapi unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102988
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102988; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102984
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|winreg|00|"; within:8; distance:51; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102984; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102989
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102989; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102985
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB winreg unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|w|00|i|00|n|00|r|00|e|00|g|00 00 00|"; within:16; distance:51; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102985; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB winreg unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102982
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ADMIN$ andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"ADMIN|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102982; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ADMIN$ andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102983
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS ADMIN$ unicode andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"A|00|D|00|M|00|I|00|N|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102983; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS ADMIN$ unicode andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102978
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS C$ andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"C|24 00|"; distance:2; nocase; content:!"IPC|24 00|"; within:5; distance:-5; nocase; classtype:protocol-command-decode; sid:2102978; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS C$ andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102979
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS C$ unicode andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"C|00 24 00 00 00|"; distance:2; nocase; content:!"I|00|P|00|C|00 24 00 00 00|"; within:10; distance:-10; nocase; classtype:protocol-command-decode; sid:2102979; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS C$ unicode andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102974
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS D$ andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"D|24 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102974; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS D$ andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102975
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS D$ unicode andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"D|00 24 00 00 00|"; distance:2; nocase; classtype:protocol-command-decode; sid:2102975; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS D$ unicode andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102496
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCEPRC ORPCThis request flood attempt"; flow:to_server,established; content:"|05|"; depth:1; content:"|00|"; within:1; distance:1; byte_test:1,&,1,0,relative; content:"|05|"; within:1; distance:21; content:"MEOW"; flowbits:isset,dce.isystemactivator.bind.call.attempt; threshold:type both, track by_dst, count 20, seconds 60; reference:bugtraq,8811; reference:cve,2003-0813; reference:nessus,12206; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:misc-attack; sid:2102496; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCEPRC ORPCThis request flood attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,8811|cve,2003-0813|nessus,12206|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102491
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC ISystemActivator unicode bind attempt"; flow:to_server,established; content:"|00|"; depth:1; content:"|FF|SMB%"; depth:5; offset:4; nocase; byte_test:2,&,1,5,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 05 00 0B|"; within:15; distance:4; byte_test:1,&,16,1,relative; content:"|A0 01 00 00 00 00 00 00 C0 00 00 00 00 00 00|F"; within:16; distance:29; flowbits:set,dce.isystemactivator.bind.call.attempt; reference:bugtraq,8811; reference:cve,2003-0813; reference:nessus,12206; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2102491; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC ISystemActivator unicode bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,8811|cve,2003-0813|nessus,12206|url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102385
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS DCERPC NTLMSSP invalid mechlistMIC attempt"; flow:to_server,established; content:"|FF|SMBs"; depth:5; offset:4; nocase; content:"`"; depth:1; offset:63; content:"|00 00 00|b|06 83 00 00 06|+|06 01 05 05 02|"; within:15; distance:1; content:"|06 0A|+|06 01 04 01 82|7|02 02 0A|"; distance:0; content:"|A3|>0<|A0|0"; distance:0; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12054; reference:nessus,12065; classtype:attempted-dos; sid:2102385; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS DCERPC NTLMSSP invalid mechlistMIC attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12054|nessus,12065

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102954
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IPC$ andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"IPC|24 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2102954; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IPC$ andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102955
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IPC$ unicode andx share access"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"u"; depth:1; offset:39; byte_jump:2,0,little,relative; byte_jump:2,7,little,relative; content:"I|00|P|00|C|00 24 00 00 00|"; distance:2; nocase; flowbits:set,smb.tree.connect.ipc; classtype:protocol-command-decode; sid:2102955; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS IPC$ unicode andx share access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102968
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102968; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102969
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:256,relative; content:!"|00|"; within:256; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102969; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102970
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|00 0C|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102970; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW unicode andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102971
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS NDdeSetTrustedShareW unicode little endian andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; byte_test:1,!&,16,3,relative; content:"|00|"; within:1; distance:1; content:"|0C 00|"; within:2; distance:19; isdataat:512,relative; content:!"|00 00|"; within:512; distance:12; reference:bugtraq,11372; reference:cve,2004-0206; classtype:attempted-admin; sid:2102971; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS NDdeSetTrustedShareW unicode little endian andx overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102402
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup AndX request username overflow attempt"; flow:to_server,established; content:"|00|"; depth:1; byte_test:2,>,322,2; content:"|FF|SMBs"; depth:5; offset:4; nocase; byte_test:1,<,128,6,relative; content:"|00 00 00 00|"; within:4; distance:42; byte_test:2,>,255,8,relative,little; content:!"|00|"; within:255; distance:10; reference:bugtraq,9752; reference:url,www.eeye.com/html/Research/Advisories/AD20040226.html; classtype:attempted-admin; sid:2102402; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS Session Setup AndX request username overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9752|url,www.eeye.com/html/Research/Advisories/AD20040226.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102962
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102962; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102958
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|nddeapi|00|"; within:9; distance:51; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102958; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102963
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi unicode andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.nddeapi; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:" 2_/&|C1|v|10 B5|I|07|M|07 86 19 DA|"; within:16; distance:29; flowbits:set,smb.tree.bind.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102963; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi unicode andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102959
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS nddeapi unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|n|00|d|00|d|00|e|00|a|00|p|00|i|00 00 00|"; within:18; distance:51; nocase; flowbits:set,smb.tree.create.nddeapi; reference:bugtraq,11372; reference:cve,2004-0206; classtype:protocol-command-decode; sid:2102959; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS nddeapi unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,11372|cve,2004-0206

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102951
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS too many stacked requests"; flow:to_server,established; content:"|FF|SMB"; pcre:"/^\x00.{3}\xFFSMB(\x73|\x74|\x75|\xa2|\x24|\x2d|\x2e|\x2f).{28}(\x73|\x74|\x75|\xa2|\x24|\x2d|\x2e|\x2f)/"; byte_jump:2,39,little; content:!"|FF|"; within:1; distance:-36; classtype:protocol-command-decode; sid:2102951; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS too many stacked requests** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102990
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg andx bind attempt"; flow:established,to_server; flowbits:isset,smb.tree.create.winreg; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-10,relative,from_beginning; pcre:"/^.{4}/R"; content:"|05|"; within:1; content:"|0B|"; within:1; distance:1; content:"|01 D0 8C|3D|22 F1|1|AA AA 90 00|8|00 10 03|"; within:16; distance:29; flowbits:set,smb.tree.bind.winreg; classtype:protocol-command-decode; sid:2102990; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg andx bind attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102986
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C|winreg|00|"; within:8; distance:51; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102986; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102987
`alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS winreg unicode andx create tree attempt"; flow:established,to_server; flowbits:isset,smb.tree.connect.ipc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"|A2|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|5C 00|w|00|i|00|n|00|r|00|e|00|g|00 00 00|"; within:16; distance:51; nocase; flowbits:set,smb.tree.create.winreg; classtype:protocol-command-decode; sid:2102987; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS winreg unicode andx create tree attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102923
`alert tcp $HOME_NET 139 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB repeated logon failure"; flow:from_server,established; content:"|FF|SMB"; depth:4; offset:4; content:"s"; within:1; content:"m|00 00 C0|"; within:4; threshold:type threshold,track by_dst,count 10,seconds 60; classtype:unsuccessful-user; sid:2102923; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB repeated logon failure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102924
`alert tcp $HOME_NET 445 -> $EXTERNAL_NET any (msg:"GPL NETBIOS SMB-DS repeated logon failure"; flow:from_server,established; content:"|FF|SMB"; depth:4; offset:4; content:"s"; within:1; content:"m|00 00 C0|"; within:4; threshold:type threshold,track by_dst,count 10,seconds 60; classtype:unsuccessful-user; sid:2102924; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB-DS repeated logon failure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101239
`alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS RFParalyze Attempt"; flow:to_server,established; content:"BEAVIS"; content:"yep yep"; reference:bugtraq,1163; reference:cve,2000-0347; reference:nessus,10392; classtype:attempted-recon; sid:2101239; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RFParalyze Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,1163|cve,2000-0347|nessus,10392

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102950
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB too many stacked requests"; flow:to_server,established; content:"|FF|SMB"; pcre:"/^\x00.{3}\xFFSMB(\x73|\x74|\x75|\xa2|\x24|\x2d|\x2e|\x2f).{28}(\x73|\x74|\x75|\xa2|\x24|\x2d|\x2e|\x2f)/"; byte_jump:2,39,little; content:!"|FF|"; within:1; distance:-36; classtype:protocol-command-decode; sid:2102950; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB too many stacked requests** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103043
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB NT Trans NT CREATE andx invalid SACL ace size dos attempt"; flow:stateless; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"|A0|"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"|01 00|"; within:2; distance:37; byte_jump:4,-7,little,relative,from_beginning; content:!"|00 00 00 00|"; within:4; distance:16; byte_jump:4,16,relative,little; content:"|00 00|"; within:2; distance:-10; classtype:protocol-command-decode; sid:2103043; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB NT Trans NT CREATE andx invalid SACL ace size dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103000
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB Session Setup NTMLSSP unicode asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,&,128,6,relative; byte_test:4,&,2147483648,48,relative,little; content:!"NTLMSSP"; within:7; distance:54; asn1:double_overflow, bitstring_overflow, relative_offset 54, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2103000; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMB Session Setup NTMLSSP unicode asn1 overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,9633|bugtraq,9635|cve,2003-0818|nessus,12052|nessus,12065|url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : NETBIOS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025090
`#alert tcp any any -> any [139,445] (msg:"ET NETBIOS Tree Connect AndX Request IPC$ Unicode"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBu"; within:5; distance:3; content:"| 00 5c 00 69 00 70 00 63 00 24 00 00 00|"; nocase; flowbits:set,smb.tree.connect.ipc; flowbits:noalert;  metadata: former_category NETBIOS; reference:cve,2006-4691; classtype:protocol-command-decode; sid:2025090; rev:1; metadata:created_at 2016_06_14, updated_at 2017_11_29;)
` 

Name : **Tree Connect AndX Request IPC$ Unicode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : cve,2006-4691

CVE reference : Not defined

Creation date : 2016-06-14

Last modified date : 2017-11-29

Rev version : 1

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025790
`alert tcp $HOME_NET [445,139] -> any any (msg:"ET NETBIOS PolarisOffice Insecure Library Loading - SMB ASCII"; flow:from_server; content:"SMB"; offset:4; depth:5; byte_test:1,!&,0x80,7,relative; content:"puiframeworkproresenu|2E|dll"; nocase; distance:0; fast_pattern; reference:url, exploit-db.com/exploits/44985/; metadata: former_category NETBIOS; reference:cve,2018-12589; classtype:attempted-user; sid:2025790; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, created_at 2018_07_06, updated_at 2018_07_18;)
` 

Name : **PolarisOffice Insecure Library Loading - SMB ASCII** 

Attack target : Client_Endpoint

Description : This signature will detect an attempt to exploit an Insecure Library Loading vulnerability in PolarisOffice

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2018-12589

CVE reference : Not defined

Creation date : 2018-07-06

Last modified date : 2018-07-18

Rev version : 1

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025791
`alert tcp $HOME_NET [445,139] -> any any (msg:"ET NETBIOS PolarisOffice Insecure Library Loading - SMB Unicode"; flow:from_server; content:"SMB"; offset:4; depth:5; byte_test:1,&,0x80,7,relative; content:"p|00|u|00|i|00|f|00|r|00|a|00|m|00|e|00|w|00|o|00|r|00|k|00|p|00|r|00|o|00|r|00|e|00|s|00|e|00|n|00|u|00 2E 00|d|00|l|00|l|00|"; nocase; distance:0; reference:url, exploit-db.com/exploits/44985/; metadata: former_category NETBIOS; reference:cve,2018-12589; classtype:attempted-user; sid:2025791; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, created_at 2018_07_06, updated_at 2018_07_18;)
` 

Name : **PolarisOffice Insecure Library Loading - SMB Unicode** 

Attack target : Client_Endpoint

Description : This signature will detect an attempt to exploit an Insecure Library Loading vulnerability in PolarisOffice

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2018-12589

CVE reference : Not defined

Creation date : 2018-07-06

Last modified date : 2018-07-18

Rev version : 1

Category : NETBIOS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025824
`alert tcp any any -> $HOME_NET 445 (msg:"ET NETBIOS Microsoft Windows RRAS SMB Remote Code Execution"; flow:established,to_server; content:"|21 00 00 00 10 27 00 00 a4 86 01 00 41 41 41 41 04 00 00 00 41 41 41 41 a4 86 01 00 ad 0b 2d 06 d0 ba 61 41 41 90 90 90 90 90|"; metadata: former_category NETBIOS; reference:cve,2017-11885; reference:url,exploit-db.com/exploits/44616/; classtype:attempted-user; sid:2025824; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, deployment Datacenter, signature_severity Major, created_at 2018_07_11, performance_impact Low, updated_at 2018_07_18;)
` 

Name : **Microsoft Windows RRAS SMB Remote Code Execution** 

Attack target : Client_and_Server

Description : This signature will detect an attempt to exploit a Remote Code Execution in Windows

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : cve,2017-11885|url,exploit-db.com/exploits/44616/

CVE reference : Not defined

Creation date : 2018-07-11

Last modified date : 2018-07-18

Rev version : 1

Category : NETBIOS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027167
`#alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC WMI Remote Process Execution"; flow:to_server,established; dce_iface:00000143-0000-0000-c000-000000000046; metadata: former_category NETBIOS; classtype:bad-unknown; sid:2027167; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Internal, signature_severity Informational, created_at 2019_04_09, updated_at 2019_04_09;)
` 

Name : **DCERPC WMI Remote Process Execution** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-09

Last modified date : 2019-04-09

Rev version : 1

Category : NETBIOS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027189
`alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC DCOM ExecuteShellCommand Call - Likely Lateral Movement"; flow:established,to_server; content:"|00|E|00|x|00|e|00|c|00|u|00|t|00|e|00|S|00|h|00|e|00|l|00|l|00|C|00|o|00|m|00|m|00|a|00|n|00|d|00|"; metadata: former_category NETBIOS; reference:url,enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/; reference:url,enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/; reference:url,attack.mitre.org/techniques/T1175/; classtype:bad-unknown; sid:2027189; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Internal, signature_severity Minor, created_at 2019_04_11, updated_at 2019_04_11;)
` 

Name : **DCERPC DCOM ExecuteShellCommand Call - Likely Lateral Movement** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/|url,enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/|url,attack.mitre.org/techniques/T1175/

CVE reference : Not defined

Creation date : 2019-04-11

Last modified date : 2019-04-11

Rev version : 1

Category : NETBIOS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027190
`#alert tcp any any -> $HOME_NET any (msg:"ET NETBIOS DCERPC DCOM ShellExecute - Likely Lateral Movement"; flow:established,to_server; content:"|00|S|00|h|00|e|00|l|00|l|00|E|00|x|00|e|00|c|00|u|00|t|00|e|00|"; metadata: former_category NETBIOS; reference:url,enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/; reference:url,enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/; reference:url,attack.mitre.org/techniques/T1175/; classtype:bad-unknown; sid:2027190; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Internal, signature_severity Minor, created_at 2019_04_11, updated_at 2019_04_11;)
` 

Name : **DCERPC DCOM ShellExecute - Likely Lateral Movement** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/|url,enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/|url,attack.mitre.org/techniques/T1175/

CVE reference : Not defined

Creation date : 2019-04-11

Last modified date : 2019-04-11

Rev version : 1

Category : NETBIOS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027237
`alert tcp any any -> $HOME_NET 135 (msg:"ET NETBIOS DCERPC SVCCTL - Remote Service Control Manager Access"; flow:established,to_server; content:"|00 00 00 00 00 00 00 00|"; content:"|13 00 0d 81 bb 7a 36 44 98 f1 35 ad 32 98 f0 38 00 10 03|"; distance:0; within:100; metadata: former_category RPC; classtype:attempted-user; sid:2027237; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, signature_severity Major, created_at 2019_04_22, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **DCERPC SVCCTL - Remote Service Control Manager Access** 

Attack target : Client_and_Server

Description : Alerts on Windows remote service control manager access.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-22

Last modified date : 2019-04-22

Rev version : 2

Category : RPC

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

