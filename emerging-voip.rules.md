# 2003192
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP INVITE Message Flood TCP"; flow:established,to_server; content:"INVITE"; depth:6; threshold: type both , track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2003192; classtype:attempted-dos; sid:2003192; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **INVITE Message Flood TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2003192

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009698
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP INVITE Message Flood UDP"; content:"INVITE"; depth:6; threshold: type both , track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2009698; classtype:attempted-dos; sid:2009698; rev:1; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **INVITE Message Flood UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2009698

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003193
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP REGISTER Message Flood TCP"; flow:established,to_server; content:"REGISTER"; depth:8; threshold: type both , track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2003193; classtype:attempted-dos; sid:2003193; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **REGISTER Message Flood TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2003193

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009699
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP REGISTER Message Flood UDP"; content:"REGISTER"; depth:8; threshold: type both , track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2009699; classtype:attempted-dos; sid:2009699; rev:1; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **REGISTER Message Flood UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2009699

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002848
`#alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP SIP UDP Softphone INVITE overflow"; dsize:>1000; content:"INVITE"; depth:6; nocase; pcre:"/\r?\n\r?\n/R"; isdataat:1000,relative; reference:bugtraq,16213; reference:cve,2006-0189; reference:url,doc.emergingthreats.net/bin/view/Main/2002848; classtype:attempted-user; sid:2002848; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SIP UDP Softphone INVITE overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,16213|cve,2006-0189|url,doc.emergingthreats.net/bin/view/Main/2002848

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003237
`#alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP MultiTech SIP UDP Overflow"; content:"INVITE"; nocase; depth:6; isdataat:65,relative; content:!"|0a|"; within:61; reference:cve,2005-4050; reference:url,doc.emergingthreats.net/2003237; classtype:attempted-user; sid:2003237; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MultiTech SIP UDP Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2005-4050|url,doc.emergingthreats.net/2003237

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003194
`alert tcp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses TCP"; flow:established,from_server; content:"SIP/2.0 401 Unauthorized"; depth:24; threshold: type both, track by_src, count 5, seconds 360; reference:url,doc.emergingthreats.net/2003194; classtype:attempted-dos; sid:2003194; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Multiple Unauthorized SIP Responses TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2003194

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009700
`alert udp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses UDP"; content:"SIP/2.0 401 Unauthorized"; depth:24; threshold: type both, track by_src, count 5, seconds 360; reference:url,doc.emergingthreats.net/2009700; classtype:attempted-dos; sid:2009700; rev:1; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Multiple Unauthorized SIP Responses UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2009700

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003329
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET VOIP Centrality IP Phone (PA-168 Chipset) Session Hijacking"; flow:established,to_server; content:"POST "; nocase; depth:5; uricontent:"/g"; nocase; content:"back=++Back++"; nocase; pcre:"/^\/g($|[?#])/Ui"; reference:url,www.milw0rm.com/exploits/3189; reference:url,doc.emergingthreats.net/bin/view/Main/2003329; reference:cve,2007-0528; classtype:attempted-user; sid:2003329; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Centrality IP Phone (PA-168 Chipset) Session Hijacking** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.milw0rm.com/exploits/3189|url,doc.emergingthreats.net/bin/view/Main/2003329|cve,2007-0528

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003474
`#alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP Asterisk Register with no URI or Version DOS Attempt"; content:"REGISTER|0d 0a|"; nocase; depth:10; content:!"SIP/"; distance:0; reference:url,labs.musecurity.com/advisories/MU-200703-01.txt; reference:url,tools.ietf.org/html/rfc3261; reference:url,doc.emergingthreats.net/2003474; classtype:attempted-dos; sid:2003474; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Asterisk Register with no URI or Version DOS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,labs.musecurity.com/advisories/MU-200703-01.txt|url,tools.ietf.org/html/rfc3261|url,doc.emergingthreats.net/2003474

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012296
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP Modified Sipvicious Asterisk PBX User-Agent"; content:"|0d 0a|User-Agent|3A| Asterisk PBX"; nocase; threshold: type limit, count 1, seconds 60, track by_src; reference:url,blog.sipvicious.org/2010/11/distributed-sip-scanning-during.html; classtype:attempted-recon; sid:2012296; rev:2; metadata:created_at 2011_02_06, updated_at 2011_02_06;)
` 

Name : **Modified Sipvicious Asterisk PBX User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.sipvicious.org/2010/11/distributed-sip-scanning-during.html

CVE reference : Not defined

Creation date : 2011-02-06

Last modified date : 2011-02-06

Rev version : 2

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012297
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper"; content:"|0d 0a|User-Agent|3A| Zoiper"; nocase; threshold: type limit, count 1, seconds 60, track by_src; reference:url,blog.sipvicious.org/2010/12/11-million-euro-loss-in-voip-fraud-and.html; classtype:attempted-recon; sid:2012297; rev:2; metadata:created_at 2011_02_06, updated_at 2011_02_06;)
` 

Name : **Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.sipvicious.org/2010/12/11-million-euro-loss-in-voip-fraud-and.html

CVE reference : Not defined

Creation date : 2011-02-06

Last modified date : 2011-02-06

Rev version : 2

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011422
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP Possible Modified Sipvicious OPTIONS Scan"; content:"OPTIONS "; depth:8; content:"ccxllrlflgig|22|<sip|3A|100"; nocase; distance:0; reference:url,code.google.com/p/sipvicious/; reference:url,blog.sipvicious.org/; classtype:attempted-recon; sid:2011422; rev:2; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Possible Modified Sipvicious OPTIONS Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/sipvicious/|url,blog.sipvicious.org/

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 2

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100158
`alert ip any any -> any 5060 (msg:"GPL VOIP SIP INVITE message flooding"; content:"INVITE"; depth:6; threshold: type both, track by_src, count 100, seconds 60; classtype:attempted-dos; sid:2100158; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SIP INVITE message flooding** 

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

Category : VOIP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100163
`alert ip any any -> any 5060 (msg:"GPL VOIP SIP 407 Proxy Authentication Required Flood"; content:"SIP/2.0 407 Proxy Authentication Required"; depth:42; threshold: type both, track by_src, count 100, seconds 60; classtype:attempted-dos; sid:2100163; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SIP 407 Proxy Authentication Required Flood** 

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

Category : VOIP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100223
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"GPL VOIP EXPLOIT SIP UDP Softphone overflow attempt"; content:"|3B|branch|3D|"; content:"a|3D|"; pcre:"/^a\x3D[^\n]{1000,}/smi"; reference:bugtraq,16213; reference:cve,2006-0189; classtype:misc-attack; sid:2100223; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **EXPLOIT SIP UDP Softphone overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,16213|cve,2006-0189

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : VOIP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100162
`alert ip any 5060 -> any any (msg:"GPL VOIP SIP 401 Unauthorized Flood"; content:"SIP/2.0 401 Unauthorized"; depth:24; threshold: type both, track by_dst, count 100, seconds 60; classtype:attempted-dos; sid:2100162; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SIP 401 Unauthorized Flood** 

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

Category : VOIP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021066
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1720 (msg:"ET VOIP Possible Misuse Call from Cisco ooh323"; flow:to_server,established; content:"|28 06|cisco|00|"; offset:14; depth:8; content:"|b8 00 00 27 05|ooh323|06|"; distance:0; within:60; reference:url,videonationsltd.co.uk/2015/04/h-323-cisco-spam-calls/; classtype:misc-attack; sid:2021066; rev:1; metadata:created_at 2015_05_07, updated_at 2015_05_07;)
` 

Name : **Possible Misuse Call from Cisco ooh323** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,videonationsltd.co.uk/2015/04/h-323-cisco-spam-calls/

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2015-05-07

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022022
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1720 (msg:"ET VOIP Possible Misuse Call from MERA RTU"; flow:to_server,established; content:"|22 c0 09 00 7a b7 07|MERA RTU|08|"; classtype:misc-attack; sid:2022022; rev:1; metadata:created_at 2015_11_02, updated_at 2015_11_02;)
` 

Name : **Possible Misuse Call from MERA RTU** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-02

Last modified date : 2015-11-02

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022023
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 1720 (msg:"ET VOIP Q.931 Call Setup - Inbound"; flow:to_server,established; content:"|08|"; offset:4; depth:1; content:"|05 04|"; distance:3; within:2; classtype:misc-activity; sid:2022023; rev:1; metadata:created_at 2015_11_02, updated_at 2015_11_02;)
` 

Name : **Q.931 Call Setup - Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-02

Last modified date : 2015-11-02

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022024
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1720 (msg:"ET VOIP H.323 in Q.931 Call Setup - Inbound"; flow:to_server,established; content:"|08|"; offset:4; depth:1; byte_jump:1,0,relative; content:"|05 04|"; within:2; byte_jump:1,0,relative; content:"|70|"; byte_jump:1,0,relative; content:"|7E|"; within:1; byte_test:1,!&,0x0F,3,relative; isdataat:31; classtype:misc-activity; sid:2022024; rev:1; metadata:created_at 2015_11_02, updated_at 2015_11_02;)
` 

Name : **H.323 in Q.931 Call Setup - Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-02

Last modified date : 2015-11-02

Rev version : 1

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

