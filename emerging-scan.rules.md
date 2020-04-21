# 2010371
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Amap TCP Service Scan Detected"; flow:to_server; flags:PA; content:"service|3A|thc|3A 2F 2F|"; depth:105; content:"service|3A|thc"; within:40; reference:url,freeworld.thc.org/thc-amap/; reference:url,doc.emergingthreats.net/2010371; classtype:attempted-recon; sid:2010371; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Amap TCP Service Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,freeworld.thc.org/thc-amap/|url,doc.emergingthreats.net/2010371

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010372
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Amap UDP Service Scan Detected"; dsize:<135; content:"THCTHCTHCTHCTHC|20 20 20|"; reference:url,freeworld.thc.org/thc-amap/; reference:url,doc.emergingthreats.net/2010372; classtype:attempted-recon; sid:2010372; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Amap UDP Service Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,freeworld.thc.org/thc-amap/|url,doc.emergingthreats.net/2010372

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008414
`alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:"ET SCAN Cisco Torch TFTP Scan"; content:"|52 61 6E 64 30 6D 53 54 52 49 4E 47 00 6E 65 74 61 73 63 69 69|"; offset:2; depth:21; reference:url,www.hackingexposedcisco.com/?link=tools; reference:url,www.securiteam.com/tools/5EP0F1FEUA.html; reference:url,doc.emergingthreats.net/2008414; classtype:attempted-recon; sid:2008414; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Torch TFTP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.hackingexposedcisco.com/?link=tools|url,www.securiteam.com/tools/5EP0F1FEUA.html|url,doc.emergingthreats.net/2008414

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010642
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET SCAN Multiple FTP Root Login Attempts from Single Source - Possible Brute Force Attempt"; flow:established,to_server; content:"USER "; nocase; depth:5; content:"root"; within:15; nocase; threshold: type threshold, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2010642; classtype:attempted-recon; sid:2010642; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Multiple FTP Root Login Attempts from Single Source - Possible Brute Force Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010642

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010643
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET SCAN Multiple FTP Administrator Login Attempts from Single Source - Possible Brute Force Attempt"; flow:established,to_server; content:"USER "; nocase; depth:5; content:"administrator"; within:25; nocase; threshold: type threshold, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2010643; classtype:attempted-recon; sid:2010643; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Multiple FTP Administrator Login Attempts from Single Source - Possible Brute Force Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010643

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007802
`alert tcp any any -> any 21 (msg:"ET SCAN Grim's Ping ftp scanning tool"; flow:to_server,established; content:"PASS "; content:"gpuser@home.com"; within:18; reference:url,archives.neohapsis.com/archives/snort/2002-04/0448.html; reference:url,grimsping.cjb.net; reference:url,doc.emergingthreats.net/2007802; classtype:network-scan; sid:2007802; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Grim's Ping ftp scanning tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,archives.neohapsis.com/archives/snort/2002-04/0448.html|url,grimsping.cjb.net|url,doc.emergingthreats.net/2007802

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000575
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ICMP PING IPTools"; itype: 8; icode: 0; content:"|A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7 A7|"; depth: 64; reference:url,www.ks-soft.net/ip-tools.eng; reference:url,www.ks-soft.net/ip-tools.eng/index.htm; reference:url,doc.emergingthreats.net/2000575; classtype:misc-activity; sid:2000575; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICMP PING IPTools** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.ks-soft.net/ip-tools.eng|url,www.ks-soft.net/ip-tools.eng/index.htm|url,doc.emergingthreats.net/2000575

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008560
`alert udp $EXTERNAL_NET any -> $HOME_NET 1434 (msg:"ET SCAN NNG MS02-039 Exploit False Positive Generator - May Conceal A Genuine Attack"; content:"nng Snort (Snort)"; offset:90; threshold:type threshold, track by_dst, count 4, seconds 15; reference:url,packetstormsecurity.nl/filedesc/nng-4.13r-public.rar.html; reference:url,doc.emergingthreats.net/2008560; classtype:misc-activity; sid:2008560; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NNG MS02-039 Exploit False Positive Generator - May Conceal A Genuine Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,packetstormsecurity.nl/filedesc/nng-4.13r-public.rar.html|url,doc.emergingthreats.net/2008560

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009286
`#alert tcp any any -> any 502 (msg:"ET SCAN Modbus Scanning detected"; content:"|00 00 00 00 00 02|"; flow:established,to_server; depth:6; threshold: type both, track by_src, count 100, seconds 10; reference:url,code.google.com/p/modscan/; reference:url,www.rtaautomation.com/modbustcp/; reference:url,doc.emergingthreats.net/2009286; classtype:bad-unknown; sid:2009286; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Modbus Scanning detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,code.google.com/p/modscan/|url,www.rtaautomation.com/modbustcp/|url,doc.emergingthreats.net/2009286

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001906
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"ET SCAN MYSQL 4.0 brute force root login attempt"; flow:to_server,established; content:"|01|"; offset:3; depth:4; content:"root|00|"; nocase; distance:5; within:5; threshold:type both,track by_src,count 5,seconds 60; reference:url,www.redferni.uklinux.net/mysql/MySQL-323.html; reference:url,doc.emergingthreats.net/2001906; classtype:protocol-command-decode; sid:2001906; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MYSQL 4.0 brute force root login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,www.redferni.uklinux.net/mysql/MySQL-323.html|url,doc.emergingthreats.net/2001906

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002842
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"ET SCAN MYSQL 4.1 brute force root login attempt"; flow:to_server,established; content:"|01|"; offset:3; depth:4; content:"root|00|"; nocase; distance:32; within:5; threshold:type both,track by_src,count 5,seconds 60; reference:url,www.redferni.uklinux.net/mysql/MySQL-Protocol.html; reference:url,doc.emergingthreats.net/2002842; classtype:protocol-command-decode; sid:2002842; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MYSQL 4.1 brute force root login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,www.redferni.uklinux.net/mysql/MySQL-Protocol.html|url,doc.emergingthreats.net/2002842

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010493
`alert tcp $HOME_NET 3306 -> any any (msg:"ET SCAN Non-Allowed Host Tried to Connect to MySQL Server"; flow:from_server,established; content:"|6A 04|Host|20 27|"; depth:70; content:"|27 20|is not allowed to connect to this MySQL server"; distance:0; reference:url,www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html; reference:url,doc.emergingthreats.net/2010493; classtype:attempted-recon; sid:2010493; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Non-Allowed Host Tried to Connect to MySQL Server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html|url,doc.emergingthreats.net/2010493

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000537
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 2048"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000537; classtype:attempted-recon; sid:2000537; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sS window 2048** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000537

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000536
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sO"; dsize:0; ip_proto:21; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000536; classtype:attempted-recon; sid:2000536; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sO** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000536

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000538
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (1)"; fragbits:!D; dsize:0; flags:A,12; window:1024; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000538; classtype:attempted-recon; sid:2000538; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sA (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000538

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000540
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sA (2)"; fragbits:!D; dsize:0; flags:A,12; window:3072; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000540; classtype:attempted-recon; sid:2000540; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sA (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000540

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000543
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sF"; fragbits:!M; dsize:0; flags:F,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000543; classtype:attempted-recon; sid:2000543; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -f -sF** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000543

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000544
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sN"; fragbits:!M; dsize:0; flags:0,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000544; classtype:attempted-recon; sid:2000544; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -f -sN** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000544

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000546
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sX"; fragbits:!M; dsize:0; flags:FPU,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000546; classtype:attempted-recon; sid:2000546; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -f -sX** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000546

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009767
`#alert udp $HOME_NET 137 -> $EXTERNAL_NET any (msg:"ET SCAN Multiple NBTStat Query Responses to External Destination, Possible Automated Windows Network Enumeration"; content:"|20 43 4b 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00 00 21|"; depth:55; threshold: type threshold, track by_dst, count 10, seconds 60; reference:url,technet.microsoft.com/en-us/library/cc940106.aspx; reference:url,doc.emergingthreats.net/2009767; classtype:attempted-recon; sid:2009767; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Multiple NBTStat Query Responses to External Destination, Possible Automated Windows Network Enumeration** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,technet.microsoft.com/en-us/library/cc940106.aspx|url,doc.emergingthreats.net/2009767

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009768
`#alert udp $HOME_NET 137 -> $EXTERNAL_NET any (msg:"ET SCAN NBTStat Query Response to External Destination, Possible Windows Network Enumeration"; content:"|20 43 4b 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00 00 21|"; depth:55; reference:url,technet.microsoft.com/en-us/library/cc940106.aspx; reference:url,doc.emergingthreats.net/2009768; classtype:attempted-recon; sid:2009768; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NBTStat Query Response to External Destination, Possible Windows Network Enumeration** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,technet.microsoft.com/en-us/library/cc940106.aspx|url,doc.emergingthreats.net/2009768

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008179
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET SCAN PRO Search Crawler Probe"; flow:to_server,established; content:"PASS "; nocase; depth:5; content:"crawler"; nocase; within:30; pcre:"/^PASS\s+PRO(-|\s)*search\s+Crawler/smi"; reference:url,sourceforge.net/project/showfiles.php?group_id=149797; reference:url,doc.emergingthreats.net/2008179; classtype:not-suspicious; sid:2008179; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **PRO Search Crawler Probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,sourceforge.net/project/showfiles.php?group_id=149797|url,doc.emergingthreats.net/2008179

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008578
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sipvicious Scan"; content:"From|3A 20 22|sipvicious"; threshold: type limit, count 1, seconds 10, track by_src; reference:url,blog.sipvicious.org; reference:url,doc.emergingthreats.net/2008578; classtype:attempted-recon; sid:2008578; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sipvicious Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.sipvicious.org|url,doc.emergingthreats.net/2008578

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011766
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Modified Sipvicious User-Agent Detected (sundayddr)"; content:"|0d 0a|User-Agent|3A| sundayddr"; threshold: type limit, count 1, seconds 60, track by_src; reference:url,honeynet.org.au/?q=sunday_scanner; reference:url,code.google.com/p/sipvicious/; reference:url,blog.sipvicious.org/; reference:url,doc.emergingthreats.net/2011766; classtype:attempted-recon; sid:2011766; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Modified Sipvicious User-Agent Detected (sundayddr)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,honeynet.org.au/?q=sunday_scanner|url,code.google.com/p/sipvicious/|url,blog.sipvicious.org/|url,doc.emergingthreats.net/2011766

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008598
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sipsak SIP scan"; content:"sip|3a|sipsak@"; offset:90; reference:url,sipsak.org/; reference:url,doc.emergingthreats.net/2008598; classtype:attempted-recon; sid:2008598; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sipsak SIP scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sipsak.org/|url,doc.emergingthreats.net/2008598

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008609
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sivus VOIP Vulnerability Scanner SIP Scan"; content:"SIVuS_VoIP_Scanner <sip|3a|SIVuS"; offset:130; threshold:type threshold, track by_src, count 3, seconds 10; reference:url,www.security-database.com/toolswatch/SiVus-VoIP-Security-Scanner-1-09.html; reference:url,www.vopsecurity.org/; reference:url,doc.emergingthreats.net/2008609; classtype:attempted-recon; sid:2008609; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sivus VOIP Vulnerability Scanner SIP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.security-database.com/toolswatch/SiVus-VoIP-Security-Scanner-1-09.html|url,www.vopsecurity.org/|url,doc.emergingthreats.net/2008609

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008610
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sivus VOIP Vulnerability Scanner SIP Components Scan"; content:"sip|3a|sivus-discovery@vopsecurity.org"; offset:110; reference:url,www.security-database.com/toolswatch/SiVus-VoIP-Security-Scanner-1-09.html; reference:url,www.vopsecurity.org/; reference:url,doc.emergingthreats.net/2008610; classtype:attempted-recon; sid:2008610; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sivus VOIP Vulnerability Scanner SIP Components Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.security-database.com/toolswatch/SiVus-VoIP-Security-Scanner-1-09.html|url,www.vopsecurity.org/|url,doc.emergingthreats.net/2008610

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008094
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"ET SCAN External to Internal UPnP Request udp port 1900"; content:"MSEARCH * HTTP/1.1"; depth:18; content:"MAN|3a| ssdp|3a|"; nocase; distance:0; reference:url,www.upnp-hacks.org/upnp.html; reference:url,doc.emergingthreats.net/2008094; classtype:attempted-recon; sid:2008094; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **External to Internal UPnP Request udp port 1900** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.upnp-hacks.org/upnp.html|url,doc.emergingthreats.net/2008094

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008526
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Smap VOIP Device Scan"; content:"<sip|3a|smap@"; offset:80; depth:40; reference:url,www.go2linux.org/smap-find-voip-enabled-devices; reference:url,doc.emergingthreats.net/2008526; classtype:attempted-recon; sid:2008526; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Smap VOIP Device Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.go2linux.org/smap-find-voip-enabled-devices|url,doc.emergingthreats.net/2008526

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008568
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Voiper Toolkit Torturer Scan"; content:"interesting-Method"; content:"sip|3a|1_unusual.URI"; content:"to-be!sure"; offset:20; depth:60; reference:url,sourceforge.net/projects/voiper; reference:url,doc.emergingthreats.net/2008568; classtype:attempted-recon; sid:2008568; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Voiper Toolkit Torturer Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sourceforge.net/projects/voiper|url,doc.emergingthreats.net/2008568

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008577
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Voiper Fuzzing Scan"; content:"sip|3a|tester@"; content:"Via|3a| SIP/2.0"; offset:20; depth:60; threshold: type threshold, track by_dst, count 5, seconds 15; reference:url,sourceforge.net/projects/voiper; reference:url,doc.emergingthreats.net/2008577; classtype:attempted-recon; sid:2008577; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Voiper Fuzzing Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sourceforge.net/projects/voiper|url,doc.emergingthreats.net/2008577

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009884
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET SCAN Unusually Fast 400 Error Messages (Bad Request), Possible Web Application Scan"; flow:from_server,established; content:"HTTP/1.1 400"; depth:13; threshold: type threshold, track by_dst, count 30, seconds 60; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec10.html; reference:url,support.microsoft.com/kb/247249; reference:url,doc.emergingthreats.net/2009884; classtype:attempted-recon; sid:2009884; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusually Fast 400 Error Messages (Bad Request), Possible Web Application Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec10.html|url,support.microsoft.com/kb/247249|url,doc.emergingthreats.net/2009884

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009885
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET SCAN Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack"; flow:from_server,established; content:"HTTP/1.1 404"; depth:13; threshold: type threshold, track by_dst, count 30, seconds 60; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec10.html; reference:url,en.wikipedia.org/wiki/HTTP_404; reference:url,doc.emergingthreats.net/2009885; classtype:attempted-recon; sid:2009885; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec10.html|url,en.wikipedia.org/wiki/HTTP_404|url,doc.emergingthreats.net/2009885

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003870
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN ProxyReconBot POST method to Mail"; flow:established,to_server; content:"POST "; depth:5; content:"|3A|25 HTTP/"; within:200; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2003870; classtype:misc-attack; sid:2003870; rev:7; metadata:created_at 2010_07_30, updated_at 2017_04_21;)
` 

Name : **ProxyReconBot POST method to Mail** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,doc.emergingthreats.net/2003870

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-04-21

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008640
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN SIP erase_registrations/add registrations attempt"; content:"REGISTER "; depth:9; content:"User-Agent|3a| Hacker"; reference:url,www.hackingvoip.com/sec_tools.html; reference:url,doc.emergingthreats.net/2008640; classtype:attempted-recon; sid:2008640; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SIP erase_registrations/add registrations attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.hackingvoip.com/sec_tools.html|url,doc.emergingthreats.net/2008640

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009749
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET SCAN Unusually Fast 403 Error Messages, Possible Web Application Scan"; flow:from_server,established; content:"HTTP/1.1 403"; depth:13; threshold: type threshold, track by_dst, count 35, seconds 60; reference:url,www.checkupdown.com/status/E403.html; reference:url,doc.emergingthreats.net/2009749; classtype:attempted-recon; sid:2009749; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusually Fast 403 Error Messages, Possible Web Application Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.checkupdown.com/status/E403.html|url,doc.emergingthreats.net/2009749

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009832
`alert tcp $EXTERNAL_NET any -> $HOME_NET [135,139,445,1024:2048] (msg:"ET SCAN DCERPC rpcmgmt ifids Unauthenticated BIND"; flow:established,to_server; content:"|05|"; content:"|80 bd a8 af 8a 7d c9 11 be f4 08 00 2b 10 29 89|"; distance:31; reference:url,www.symantec.com/avcenter/reference/Vista_Network_Attack_Surface_RTM.pdf; reference:url,www.blackhat.com/presentations/win-usa-04/bh-win-04-seki-up2.pdf; reference:url,seclists.org/fulldisclosure/2003/Aug/0432.html; reference:url,doc.emergingthreats.net/2009832; classtype:attempted-recon; sid:2009832; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **DCERPC rpcmgmt ifids Unauthenticated BIND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.symantec.com/avcenter/reference/Vista_Network_Attack_Surface_RTM.pdf|url,www.blackhat.com/presentations/win-usa-04/bh-win-04-seki-up2.pdf|url,seclists.org/fulldisclosure/2003/Aug/0432.html|url,doc.emergingthreats.net/2009832

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009646
`alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN Acunetix Version 6 (Free Edition) Scan Detected"; flow:to_server,established; content:"(Acunetix Web Vulnerability Scanner"; nocase; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.acunetix.com/; reference:url,doc.emergingthreats.net/2009646; classtype:attempted-recon; sid:2009646; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Acunetix Version 6 (Free Edition) Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.acunetix.com/|url,doc.emergingthreats.net/2009646

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011975
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN RatProxy in-use"; flow:established,to_server; content:"X-Ratproxy-Loop|3A| "; threshold: type limit, track by_src,count 1, seconds 60; classtype:attempted-recon; sid:2011975; rev:2; metadata:created_at 2010_11_24, updated_at 2010_11_24;)
` 

Name : **RatProxy in-use** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-11-24

Last modified date : 2010-11-24

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008579
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sipp SIP Stress Test Detected"; content:"sip|3a|sipp@"; content:"Subject|3a| Performance Test"; offset:90; depth:90; threshold: type threshold, track by_dst, count 20, seconds 15; reference:url,sourceforge.net/projects/sipp/; reference:url,doc.emergingthreats.net/2008579; classtype:attempted-recon; sid:2008579; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sipp SIP Stress Test Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sourceforge.net/projects/sipp/|url,doc.emergingthreats.net/2008579

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008641
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN sipscan probe"; content:"sip|3a|thisisthecanary@"; content:"sip|3a|test@"; offset:30; depth:70; reference:url,www.hackingvoip.com/sec_tools.html; reference:url,doc.emergingthreats.net/2008641; classtype:attempted-recon; sid:2008641; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **sipscan probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.hackingvoip.com/sec_tools.html|url,doc.emergingthreats.net/2008641

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012204
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Modified Sipvicious Sundayddr Scanner (sipsscuser)"; content:"From|3A 20 22|sipsscuser|22|"; threshold: type limit, count 1, seconds 60, track by_src; reference:url,code.google.com/p/sipvicious/; reference:url,blog.sipvicious.org/; reference:url,honeynet.org.au/?q=sunday_scanner; classtype:attempted-recon; sid:2012204; rev:3; metadata:created_at 2011_01_20, updated_at 2011_01_20;)
` 

Name : **Modified Sipvicious Sundayddr Scanner (sipsscuser)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/sipvicious/|url,blog.sipvicious.org/|url,honeynet.org.au/?q=sunday_scanner

CVE reference : Not defined

Creation date : 2011-01-20

Last modified date : 2011-01-20

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012606
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Havij SQL Injection Tool User-Agent Inbound"; flow:established,to_server; content:"|29| Havij|0d 0a|Connection|3a| "; http_header; reference:url,itsecteam.com/en/projects/project1.htm; classtype:web-application-attack; sid:2012606; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2011_03_30, updated_at 2020_04_19;)
` 

Name : **Havij SQL Injection Tool User-Agent Inbound** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,itsecteam.com/en/projects/project1.htm

CVE reference : Not defined

Creation date : 2011-03-30

Last modified date : 2020-04-19

Rev version : 4

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011924
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Havij SQL Injection Tool User-Agent Outbound"; flow:established,to_server; content:"|29| Havij|0d 0a|Connection|3a| "; http_header; reference:url,itsecteam.com/en/projects/project1.htm; classtype:web-application-attack; sid:2011924; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_11_12, updated_at 2020_04_20;)
` 

Name : **Havij SQL Injection Tool User-Agent Outbound** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,itsecteam.com/en/projects/project1.htm

CVE reference : Not defined

Creation date : 2010-11-12

Last modified date : 2020-04-20

Rev version : 3

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101918
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN SolarWinds IP scan attempt"; icode:0; itype:8; content:"SolarWinds.Net"; nocase; classtype:network-scan; sid:2101918; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SolarWinds IP scan attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012754
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible SQLMAP Scan"; flow:established,to_server; content:"UNION ALL SELECT NULL, NULL, NULL, NULL"; http_uri; content:"-- AND"; http_uri; detection_filter:track by_dst, count 4, seconds 20; reference:url,sqlmap.sourceforge.net; reference:url,www.darknet.org.uk/2011/04/sqlmap-0-9-released-automatic-blind-sql-injection-tool/; classtype:attempted-recon; sid:2012754; rev:2; metadata:created_at 2011_04_29, updated_at 2020_04_20;)
` 

Name : **Possible SQLMAP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlmap.sourceforge.net|url,www.darknet.org.uk/2011/04/sqlmap-0-9-released-automatic-blind-sql-injection-tool/

CVE reference : Not defined

Creation date : 2011-04-29

Last modified date : 2020-04-20

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100478
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Broadscan Smurf Scanner"; dsize:4; icmp_id:0; icmp_seq:0; itype:8; classtype:attempted-recon; sid:2100478; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Broadscan Smurf Scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100465
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN ISS Pinger"; itype:8; content:"ISSPNGRQ"; depth:32; reference:arachnids,158; classtype:attempted-recon; sid:2100465; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ISS Pinger** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,158

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100483
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN PING CyberKit 2.2 Windows"; itype:8; content:"|AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA|"; depth:32; reference:arachnids,154; classtype:misc-activity; sid:2100483; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING CyberKit 2.2 Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,154

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100372
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN PING Delphi-Piette Windows"; itype:8; content:"Pinging from Del"; depth:32; reference:arachnids,155; classtype:misc-activity; sid:2100372; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Delphi-Piette Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,155

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100469
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN PING NMAP"; dsize:0; itype:8; reference:arachnids,162; classtype:attempted-recon; sid:2100469; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING NMAP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,162

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100484
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN PING Sniffer Pro/NetXRay network scan"; itype:8; content:"Cinco Network, Inc."; depth:32; classtype:misc-activity; sid:2100484; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Sniffer Pro/NetXRay network scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100471
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN icmpenum v1.1.1"; dsize:0; icmp_id:666 ; icmp_seq:0; id:666; itype:8; reference:arachnids,450; classtype:attempted-recon; sid:2100471; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **icmpenum v1.1.1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,450

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100474
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN superscan echo"; dsize:8; itype:8; content:"|00 00 00 00 00 00 00 00|"; classtype:attempted-recon; sid:2100474; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **superscan echo** 

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

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100476
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN webtrends scanner"; icode:0; itype:8; content:"|00 00 00 00|EEEEEEEEEEEE"; reference:arachnids,307; classtype:attempted-recon; sid:2100476; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **webtrends scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,307

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101638
`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SCAN SSH Version map attempt"; flow:to_server,established; content:"Version_Mapper"; nocase; classtype:network-scan; sid:2101638; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SSH Version map attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100637
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Webtrends Scanner UDP Probe"; content:"|0A|help|0A|quite|0A|"; classtype:attempted-recon; sid:2100637; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Webtrends Scanner UDP Probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013263
`alert ftp any any -> $HOME_NET any (msg:"ET SCAN Nessus FTP Scan detected (ftp_anonymous.nasl)"; flow:to_server,established; content:"pass nessus@"; depth:12; nocase; reference:url,www.nessus.org/plugins/index.php?view=single&id=10079; reference:url,osvdb.org/show/osvdb/69; classtype:attempted-recon; sid:2013263; rev:3; metadata:created_at 2011_07_13, updated_at 2011_07_13;)
` 

Name : **Nessus FTP Scan detected (ftp_anonymous.nasl)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nessus.org/plugins/index.php?view=single&id=10079|url,osvdb.org/show/osvdb/69

CVE reference : Not defined

Creation date : 2011-07-13

Last modified date : 2011-07-13

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013264
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nessus FTP Scan detected (ftp_writeable_directories.nasl)"; flow:to_server,established; content:"MKD"; nocase; depth:3; content:"Nessus"; nocase; reference:url,www.nessus.org/plugins/index.php?view=single&id=19782; reference:url,osvdb.org/show/osvdb/76; classtype:attempted-recon; sid:2013264; rev:2; metadata:created_at 2011_07_13, updated_at 2011_07_13;)
` 

Name : **Nessus FTP Scan detected (ftp_writeable_directories.nasl)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nessus.org/plugins/index.php?view=single&id=19782|url,osvdb.org/show/osvdb/76

CVE reference : Not defined

Creation date : 2011-07-13

Last modified date : 2011-07-13

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101541
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Version Query"; flow:to_server,established; content:"version"; classtype:attempted-recon; sid:2101541; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Version Query** 

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

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013116
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Potential muieblackcat scanner double-URI and HTTP library"; flow:established,to_server; content:"GET //"; depth:6; fast_pattern; content:"HTTP/1.1|0d 0a|Accept|3a| */*|0d 0a|Accept-Language|3a| en-us|0d 0a|Accept-Encoding|3a| gzip, deflate|0d 0a|Host|3a| "; http_header; content:"|0d 0a|Connection|3a| Close|0d 0a 0d 0a|"; http_header; distance:0; metadata: former_category SCAN; classtype:attempted-recon; sid:2013116; rev:5; metadata:created_at 2011_06_24, updated_at 2011_06_24;)
` 

Name : **Potential muieblackcat scanner double-URI and HTTP library** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-24

Last modified date : 2011-06-24

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013472
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Kingcope KillApache.pl Apache mod_deflate DoS attempt"; flow:established,to_server; content:"Range|3a|bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10,5-11,5-12,5-13,5-14"; http_header; reference:url,seclists.org/fulldisclosure/2011/Aug/175; classtype:attempted-dos; sid:2013472; rev:4; metadata:created_at 2011_08_26, updated_at 2020_04_20;)
` 

Name : **Kingcope KillApache.pl Apache mod_deflate DoS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,seclists.org/fulldisclosure/2011/Aug/175

CVE reference : Not defined

Creation date : 2011-08-26

Last modified date : 2020-04-20

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100528
`#alert ip any any <> 127.0.0.0/8 any (msg:"GPL SCAN loopback traffic";  reference:url,rr.sans.org/firewall/egress.php; classtype:bad-unknown; sid:2100528; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **loopback traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,rr.sans.org/firewall/egress.php

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100527
`#alert ip any any -> any any (msg:"GPL SCAN same SRC/DST"; sameip; reference:bugtraq,2666; reference:cve,1999-0016; reference:url,www.cert.org/advisories/CA-1997-28.html; classtype:bad-unknown; sid:2100527; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **same SRC/DST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,2666|cve,1999-0016|url,www.cert.org/advisories/CA-1997-28.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013778
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN NMAP SQL Spider Scan"; flow:established,to_server; content:"GET"; http_method; content:" OR sqlspider"; http_uri; reference:url,nmap.org/nsedoc/scripts/sql-injection.html; classtype:web-application-attack; sid:2013778; rev:2; metadata:created_at 2011_10_19, updated_at 2020_04_20;)
` 

Name : **NMAP SQL Spider Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,nmap.org/nsedoc/scripts/sql-injection.html

CVE reference : Not defined

Creation date : 2011-10-19

Last modified date : 2020-04-20

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008187
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Paros Proxy Scanner Detected"; flow:to_server,established; content:"Paros/"; http_header; fast_pattern; pcre:"/^User-Agent\x3a[^\n]+Paros\//H"; reference:url,www.parosproxy.org; reference:url,doc.emergingthreats.net/2008187; classtype:attempted-recon; sid:2008187; rev:8; metadata:created_at 2010_07_30, updated_at 2020_04_20;)
` 

Name : **Paros Proxy Scanner Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.parosproxy.org|url,doc.emergingthreats.net/2008187

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-04-20

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100333
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger . query"; flow:to_server,established; content:"."; reference:arachnids,130; reference:cve,1999-0198; reference:nessus,10072; classtype:attempted-recon; sid:2100333; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger . query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,130|cve,1999-0198|nessus,10072

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103151
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger / execution attempt"; flow:to_server,established; content:"/"; pcre:"/^\x2f/smi"; reference:cve,1999-0612; reference:cve,2000-0915; classtype:attempted-recon; sid:2103151; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger / execution attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,1999-0612|cve,2000-0915

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100332
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger 0 Query"; flow:to_server,established; content:"0"; reference:arachnids,131; reference:arachnids,378; reference:cve,1999-0197; reference:nessus,10069; classtype:attempted-recon; sid:2100332; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger 0 Query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,131|arachnids,378|cve,1999-0197|nessus,10069

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100321
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Account Enumeration Attempt"; flow:to_server,established; content:"a b c d e f"; nocase; reference:nessus,10788; classtype:attempted-recon; sid:2100321; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Account Enumeration Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10788

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100331
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN cybercop query"; flow:to_server,established; content:"|0A|     "; depth:10; reference:arachnids,132; reference:cve,1999-0612; classtype:attempted-recon; sid:2100331; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,132|cve,1999-0612

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100329
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN cybercop redirection"; dsize:11; flow:to_server,established; content:"@localhost|0A|"; reference:arachnids,11; classtype:attempted-recon; sid:2100329; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop redirection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,11

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100324
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Null Request"; flow:to_server,established; content:"|00|"; reference:arachnids,377; classtype:attempted-recon; sid:2100324; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Null Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,377

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100325
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Probe 0 Attempt"; flow:to_server,established; content:"0"; reference:arachnids,378; classtype:attempted-recon; sid:2100325; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Probe 0 Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,378

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100330
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Redirection Attempt"; flow:to_server,established; content:"@"; reference:arachnids,251; reference:cve,1999-0105; reference:nessus,10073; classtype:attempted-recon; sid:2100330; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Redirection Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,251|cve,1999-0105|nessus,10073

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100323
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Root Query"; flow:to_server,established; content:"root"; reference:arachnids,376; classtype:attempted-recon; sid:2100323; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Root Query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,376

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100322
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL SCAN Finger Search Query"; flow:to_server,established; content:"search"; reference:arachnids,375; reference:cve,1999-0259; classtype:attempted-recon; sid:2100322; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger Search Query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,375|cve,1999-0259

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100353
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL SCAN adm scan"; flow:to_server,established; content:"PASS ddd@|0A|"; reference:arachnids,332; classtype:suspicious-login; sid:2100353; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **adm scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,332

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008654
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLix SQL Injection Vector Scan"; flow:established,to_server; content:"GET"; http_header; content:"myVAR=1234"; http_header; content:"Windows 98"; http_header; distance:36; within:120; reference:url,www.owasp.org/index.php/Category%3aOWASP_SQLiX_Project; reference:url,doc.emergingthreats.net/2008654; classtype:attempted-recon; sid:2008654; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2020_04_20;)
` 

Name : **SQLix SQL Injection Vector Scan** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,www.owasp.org/index.php/Category%3aOWASP_SQLiX_Project|url,doc.emergingthreats.net/2008654

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-04-20

Rev version : 7

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014022
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Gootkit Scanner User-Agent Inbound"; flow:established,to_server; content:"Gootkit auto-rooter scanner"; http_header; metadata: former_category SCAN; classtype:web-application-attack; sid:2014022; rev:2; metadata:created_at 2011_12_12, updated_at 2020_04_20;)
` 

Name : **Gootkit Scanner User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-12

Last modified date : 2020-04-20

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008455
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Tomcat Auth Brute Force attempt (manager)"; flow:to_server,established; content:"Authorization|3a| Basic bWFuYWdlcjp"; fast_pattern:15,17; http_header; threshold: type threshold, track by_src, count 5, seconds 30; reference:url,doc.emergingthreats.net/2008455; classtype:web-application-attack; sid:2008455; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Tomcat Auth Brute Force attempt (manager)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2008455

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008454
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Tomcat Auth Brute Force attempt (tomcat)"; flow:to_server,established; content:"Authorization|3a| Basic dG9tY2F0"; fast_pattern:15,14; http_header; threshold: type threshold, track by_src, count 5, seconds 30; reference:url,doc.emergingthreats.net/2008454; classtype:web-application-attack; sid:2008454; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Tomcat Auth Brute Force attempt (tomcat)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2008454

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008453
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Tomcat Auth Brute Force attempt (admin)"; flow:to_server,established; content:"Authorization|3a| Basic YWRtaW46"; fast_pattern:15,14; http_header; threshold: type threshold, track by_src, count 5, seconds 30; reference:url,doc.emergingthreats.net/2008453; classtype:web-application-attack; sid:2008453; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Tomcat Auth Brute Force attempt (admin)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2008453

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102585
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SCAN nessus 2.x 404 probe"; flow:to_server,established; content:"/NessusTest"; http_uri; nocase; reference:nessus,10386; classtype:attempted-recon; sid:2102585; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **nessus 2.x 404 probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10386

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008606
`alert udp $EXTERNAL_NET any -> $HOME_NET 4569 (msg:"ET SCAN Enumiax Inter-Asterisk Exchange Protocol Username Scan"; content:"|00 00|"; content:"|06 0D 06 01 30 13 02 07 08|"; distance:40; within:10; reference:url,sourceforge.net/projects/enumiax/; reference:url,doc.emergingthreats.net/2008606; classtype:attempted-recon; sid:2008606; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Enumiax Inter-Asterisk Exchange Protocol Username Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sourceforge.net/projects/enumiax/|url,doc.emergingthreats.net/2008606

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009298
`alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Port Unreachable Response to Xprobe2 OS Fingerprint Scan"; itype:3; dsize:>69; content:"securityfocus"; content:"securityfocus"; distance:50; within:15; reference:url,xprobe.sourceforge.net/; reference:url,doc.emergingthreats.net/2009298; classtype:attempted-recon; sid:2009298; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Port Unreachable Response to Xprobe2 OS Fingerprint Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,xprobe.sourceforge.net/|url,doc.emergingthreats.net/2009298

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009476
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible jBroFuzz Fuzzer Detected"; flow:to_server,established; content:"Host|3a| localhost"; fast_pattern; http_header; content:"User-Agent|3a| Mozilla/5.0 (Windows|3b| U|3b| Windows NT 5.1|3b| en-GB|3b| rv|3b|1.8.1.1) Gecko/20061204 Firefox/2.0.0.1"; http_header; threshold: type threshold, track by_src, count 3, seconds 6; reference:url,www.owasp.org/index.php/Category%3aOWASP_JBroFuzz; reference:url,doc.emergingthreats.net/2009476; classtype:attempted-recon; sid:2009476; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible jBroFuzz Fuzzer Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.owasp.org/index.php/Category%3aOWASP_JBroFuzz|url,doc.emergingthreats.net/2009476

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013249
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Vega Web Application Scan"; flow:established,to_server; content:"Vega/"; http_header; pcre:"/User-Agent\x3A[^\r\n]+Vega\x2F/H"; threshold: type limit, track by_src, count 5, seconds 40; reference:url,www.subgraph.com/products.html; reference:url,www.darknet.org.uk/2011/07/vega-open-source-cross-platform-web-application-security-assessment-platform/; classtype:attempted-recon; sid:2013249; rev:3; metadata:created_at 2011_07_11, updated_at 2011_07_11;)
` 

Name : **Vega Web Application Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.subgraph.com/products.html|url,www.darknet.org.uk/2011/07/vega-open-source-cross-platform-web-application-security-assessment-platform/

CVE reference : Not defined

Creation date : 2011-07-11

Last modified date : 2011-07-11

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014893
`#alert tcp [184.154.42.194,50.116.22.209,69.64.43.135,69.64.43.137,69.64.43.142,216.17.107.104,216.17.102.194,216.17.106.90,216.17.107.174,64.6.100.124,46.17.98.214] any -> $HOME_NET any (msg:"ET SCAN critical.io Scan"; threshold: type limit, track by_src, seconds 3600, count 1; reference:url,critical.io/; classtype:network-scan; sid:2014893; rev:5; metadata:created_at 2012_06_14, updated_at 2012_06_14;)
` 

Name : **critical.io Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,critical.io/

CVE reference : Not defined

Creation date : 2012-06-14

Last modified date : 2012-06-14

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015552
`alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN HTExploit Method"; flow:established,to_server; dsize:>6; content:"POTATO "; depth:7; reference:url,www.mkit.com.ar/labs/htexploit/download.php; classtype:trojan-activity; sid:2015552; rev:2; metadata:created_at 2012_07_31, updated_at 2012_07_31;)
` 

Name : **HTExploit Method** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.mkit.com.ar/labs/htexploit/download.php

CVE reference : Not defined

Creation date : 2012-07-31

Last modified date : 2012-07-31

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100623
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NULL"; flow:stateless; ack:0; flags:0; seq:0; reference:arachnids,4; classtype:attempted-recon; sid:2100623; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NULL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,4

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100625
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN XMAS"; flow:stateless; flags:SRAFPU,12; reference:arachnids,144; classtype:attempted-recon; sid:2100625; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **XMAS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,144

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100626
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN cybercop os PA12 attempt"; flow:stateless; flags:PA12; content:"AAAAAAAAAAAAAAAA"; depth:16; reference:arachnids,149; classtype:attempted-recon; sid:2100626; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop os PA12 attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,149

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100627
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN cybercop os SFU12 probe"; flow:stateless; ack:0; flags:SFU12; content:"AAAAAAAAAAAAAAAA"; depth:16; reference:arachnids,150; classtype:attempted-recon; sid:2100627; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop os SFU12 probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,150

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100628
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN nmap TCP"; ack:0; flags:A,12; flow:stateless; reference:arachnids,28; classtype:attempted-recon; sid:2100628; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **nmap TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,28

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101228
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN nmap XMAS"; flow:stateless; flags:FPU,12; reference:arachnids,30; classtype:attempted-recon; sid:2101228; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **nmap XMAS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,30

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100629
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN nmap fingerprint attempt"; flags:SFPU; flow:stateless; reference:arachnids,05; classtype:attempted-recon; sid:2100629; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **nmap fingerprint attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,05

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100989
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SCAN sensepost.exe command shell attempt"; flow:to_server,established; content:"/sensepost.exe"; http_uri; nocase; reference:nessus,11003; classtype:web-application-activity; sid:2100989; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sensepost.exe command shell attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,11003

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100613
`#alert tcp $EXTERNAL_NET 10101 -> $HOME_NET any (msg:"GPL SCAN myscan"; flow:stateless; ack:0; flags:S; ttl:>220; reference:arachnids,439; classtype:attempted-recon; sid:2100613; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **myscan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,439

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100624
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN SYN FIN"; flow:stateless; flags:SF,12; reference:arachnids,198; classtype:attempted-recon; sid:2100624; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SYN FIN** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,198

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100612
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN rusers query UDP"; content:"|00 01 86 A2|"; depth:4; offset:12; content:"|00 00 00 02|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:cve,1999-0626; classtype:attempted-recon; sid:2100612; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rusers query UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,1999-0626

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100617
`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SCAN ssh-research-scanner"; flow:to_server,established; content:"|00 00 00|`|00 00 00 00 00 00 00 00 01 00 00 00|"; classtype:attempted-recon; sid:2100617; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ssh-research-scanner** 

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

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102230
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN NetGear router default password login attempt admin/password"; flow:to_server,established; content:"Authorization|3A|"; http_header; nocase; content:"YWRtaW46cGFzc3dvcmQ"; distance:0; http_header; pcre:"/^Authorization\x3a\s*Basic\s+YWRtaW46cGFzc3dvcmQ/Hi"; reference:nessus,11737; classtype:default-login-attempt; sid:2102230; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NetGear router default password login attempt admin/password** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : default-login-attempt

URL reference : nessus,11737

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101133
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL SCAN cybercop os probe"; flow:stateless; ack:0; flags:SFP; content:"AAAAAAAAAAAAAAAA"; depth:16; reference:arachnids,145; classtype:attempted-recon; sid:2101133; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop os probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,145

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101139
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL SCAN whisker HEAD/./"; flow:to_server,established; content:"HEAD/./"; reference:url,www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html; classtype:attempted-recon; sid:2101139; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **whisker HEAD/./** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101099
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SCAN cybercop scan"; flow:to_server,established; content:"/cybercop"; http_uri; nocase; reference:arachnids,374; classtype:web-application-activity; sid:2101099; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : arachnids,374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100619
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"GPL SCAN cybercop os probe"; flow:stateless; dsize:0; flags:SF12; reference:arachnids,146; classtype:attempted-recon; sid:2100619; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cybercop os probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,146

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012936
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ZmEu Scanner User-Agent Inbound"; flow:established,to_server; content:"ZmEu"; http_user_agent; depth:4; classtype:trojan-activity; sid:2012936; rev:3; metadata:created_at 2011_06_06, updated_at 2011_06_06;)
` 

Name : **ZmEu Scanner User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-06

Last modified date : 2011-06-06

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009218
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomcat admin-blank login credentials"; flow:to_server,established; content:"/manager/html"; nocase; http_uri; content:"|0d 0a|Authorization|3a| Basic YWRtaW46|0d 0a|"; http_header; flowbits:set,ET.Tomcat.login.attempt; reference:url,tomcat.apache.org; reference:url,doc.emergingthreats.net/2009218; classtype:attempted-admin; sid:2009218; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Tomcat admin-blank login credentials** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,tomcat.apache.org|url,doc.emergingthreats.net/2009218

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009555
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Absinthe SQL Injection Tool HTTP Header Detected"; flow:established,to_server; content:"Absinthe"; nocase; http_user_agent; depth:8; reference:url,0x90.org/releases/absinthe; reference:url,doc.emergingthreats.net/2009555; classtype:attempted-recon; sid:2009555; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Absinthe SQL Injection Tool HTTP Header Detected** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,0x90.org/releases/absinthe|url,doc.emergingthreats.net/2009555

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 7

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002664
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nessus User Agent"; flow: established,to_server; content:"Nessus"; nocase; depth:40; http_user_agent; threshold: type limit, track by_src,count 1, seconds 60; reference:url,www.nessus.org; reference:url,doc.emergingthreats.net/2002664; classtype:attempted-recon; sid:2002664; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Nessus User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nessus.org|url,doc.emergingthreats.net/2002664

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009358
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)"; flow:to_server,established; content:"Mozilla/5.0 (compatible|3b| Nmap Scripting Engine"; nocase; http_user_agent; depth:46; reference:url,doc.emergingthreats.net/2009358; classtype:web-application-attack; sid:2009358; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009358

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015702
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Brutus Scan Outbound"; flow:established,to_server; content:"Brutus/AET"; http_user_agent; classtype:attempted-recon; sid:2015702; rev:3; metadata:created_at 2012_09_17, updated_at 2012_09_17;)
` 

Name : **Brutus Scan Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-17

Last modified date : 2012-09-17

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010715
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ZmEu exploit scanner"; flow:established,to_server; content:"Made by ZmEu"; http_user_agent; depth:12; threshold: type limit, track by_src, seconds 180, count 1; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2010715; classtype:web-application-attack; sid:2010715; rev:9; metadata:created_at 2010_07_30, updated_at 2018_02_14;)
` 

Name : **ZmEu exploit scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010715

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-02-14

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008228
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Suspicious User-Agent inbound (bot)"; flow:to_server,established; content:"bot/"; nocase; http_user_agent; depth:4; threshold: type limit, count 3, seconds 300, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008228; classtype:trojan-activity; sid:2008228; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Suspicious User-Agent inbound (bot)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008228

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 10

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011716
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN Sipvicious User-Agent Detected (friendly-scanner)"; content:"|0d 0a|User-Agent|3A| friendly-scanner"; threshold: type limit, track by_src, count 5, seconds 120; reference:url,code.google.com/p/sipvicious/; reference:url,blog.sipvicious.org/; reference:url,doc.emergingthreats.net/2011716; classtype:attempted-recon; sid:2011716; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sipvicious User-Agent Detected (friendly-scanner)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/sipvicious/|url,blog.sipvicious.org/|url,doc.emergingthreats.net/2011716

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014541
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN FHScan core User-Agent Detect"; flow:to_server,established; content:"FHScan Core 1."; http_user_agent; reference:url,www.tarasco.org/security/FHScan_Fast_HTTP_Vulnerability_Scanner/index.html; classtype:attempted-recon; sid:2014541; rev:5; metadata:created_at 2012_04_12, updated_at 2012_04_12;)
` 

Name : **FHScan core User-Agent Detect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.tarasco.org/security/FHScan_Fast_HTTP_Vulnerability_Scanner/index.html

CVE reference : Not defined

Creation date : 2012-04-12

Last modified date : 2012-04-12

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012755
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible SQLMAP Scan"; flow:established,to_server; content:" AND "; http_uri; content:"AND ("; http_uri; pcre:"/\x20AND\x20[0-9]{6}\x3D[0-9]{4}/U"; detection_filter:track by_dst, count 4, seconds 20; reference:url,sqlmap.sourceforge.net; reference:url,www.darknet.org.uk/2011/04/sqlmap-0-9-released-automatic-blind-sql-injection-tool/; classtype:attempted-recon; sid:2012755; rev:4; metadata:created_at 2011_04_29, updated_at 2011_04_29;)
` 

Name : **Possible SQLMAP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlmap.sourceforge.net|url,www.darknet.org.uk/2011/04/sqlmap-0-9-released-automatic-blind-sql-injection-tool/

CVE reference : Not defined

Creation date : 2011-04-29

Last modified date : 2011-04-29

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015986
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"ET SCAN MYSQL MySQL Remote FAST Account Password Cracking"; flow:to_server,established; content:"|11|"; offset:3; depth:4; threshold:type both,track by_src,count 100,seconds 1; reference:url,www.securityfocus.com/archive/1/524927/30/0/threaded; classtype:protocol-command-decode; sid:2015986; rev:5; metadata:created_at 2012_12_04, updated_at 2012_12_04;)
` 

Name : **MYSQL MySQL Remote FAST Account Password Cracking** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,www.securityfocus.com/archive/1/524927/30/0/threaded

CVE reference : Not defined

Creation date : 2012-12-04

Last modified date : 2012-12-04

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016222
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN GET with HTML tag in start of URI seen with PHPMyAdmin scanning"; flow:established,to_server; content:"<title>"; http_uri; depth:7; content:"GET"; http_method; classtype:web-application-attack; sid:2016222; rev:2; metadata:created_at 2013_01_16, updated_at 2013_01_16;)
` 

Name : **GET with HTML tag in start of URI seen with PHPMyAdmin scanning** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-16

Last modified date : 2013-01-16

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008415
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Cisco Torch IOS HTTP Scan"; flow:to_server,established; content:"Cisco-torch"; http_user_agent; reference:url,www.hackingexposedcisco.com/?link=tools; reference:url,www.securiteam.com/tools/5EP0F1FEUA.html; reference:url,doc.emergingthreats.net/2008415; classtype:attempted-recon; sid:2008415; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco Torch IOS HTTP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.hackingexposedcisco.com/?link=tools|url,www.securiteam.com/tools/5EP0F1FEUA.html|url,doc.emergingthreats.net/2008415

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008529
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Core-Project Scanning Bot UA Detected"; flow:established,to_server; content:"core-project/1.0"; http_user_agent; classtype:web-application-activity; sid:2008529; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Core-Project Scanning Bot UA Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100467
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL SCAN Nemesis v1.1 Echo"; dsize:20; icmp_id:0; icmp_seq:0; itype:8; content:"|00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; reference:arachnids,449; classtype:attempted-recon; sid:2100467; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Nemesis v1.1 Echo** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,449

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013473
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Apache mod_deflate DoS via many multiple byte Range values"; flow:established,to_server; content:"Range|3a|"; nocase; content:"bytes="; nocase; distance:0; isdataat:10,relative; content:","; within:11; isdataat:10,relative; content:","; within:11; isdataat:10,relative; content:","; within:11; isdataat:70,relative; content:!"|0d 0a|"; within:12; pcre:"/Range\x3a\s?bytes=[-0-9,\x20]{100}/iH"; reference:url,seclists.org/fulldisclosure/2011/Aug/175; classtype:attempted-dos; sid:2013473; rev:5; metadata:created_at 2011_08_26, updated_at 2011_08_26;)
` 

Name : **Apache mod_deflate DoS via many multiple byte Range values** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,seclists.org/fulldisclosure/2011/Aug/175

CVE reference : Not defined

Creation date : 2011-08-26

Last modified date : 2011-08-26

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017142
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Arachni Web Scan"; flow:established,to_server; content:"/Arachni-"; http_uri; threshold: type limit, track by_src, seconds 60, count 1; reference:url,www.arachni-scanner.com/; classtype:attempted-recon; sid:2017142; rev:2; metadata:created_at 2013_07_12, updated_at 2013_07_12;)
` 

Name : **Arachni Web Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.arachni-scanner.com/

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2013-07-12

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011031
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN HTTP GET invalid method case"; flow:established,to_server; content:"get "; depth:4; nocase; content:!"GET "; depth:4; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html; reference:url,doc.emergingthreats.net/2011031; classtype:bad-unknown; sid:2011031; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HTTP GET invalid method case** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html|url,doc.emergingthreats.net/2011031

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011032
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN HTTP POST invalid method case"; flow:established,to_server; content:"post "; depth:5; nocase; content:!"POST "; depth:5; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html; reference:url,doc.emergingthreats.net/2011032; classtype:bad-unknown; sid:2011032; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HTTP POST invalid method case** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html|url,doc.emergingthreats.net/2011032

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011033
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN HTTP HEAD invalid method case"; flow:established,to_server; content:"head "; depth:5; nocase; content:!"HEAD "; depth:5; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html; reference:url,doc.emergingthreats.net/2011033; classtype:bad-unknown; sid:2011033; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HTTP HEAD invalid method case** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html|url,doc.emergingthreats.net/2011033

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017615
`alert http $HOME_NET any -> any any (msg:"ET SCAN NETWORK Outgoing Masscan detected"; flow:established,to_server; content:"masscan/"; depth:8; http_user_agent; reference:url,blog.erratasec.com/2013/10/that-dlink-bug-masscan.html; reference:url,blog.erratasec.com/2013/09/masscan-entire-internet-in-3-minutes.html; classtype:network-scan; sid:2017615; rev:4; metadata:created_at 2013_10_18, updated_at 2013_10_18;)
` 

Name : **NETWORK Outgoing Masscan detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,blog.erratasec.com/2013/10/that-dlink-bug-masscan.html|url,blog.erratasec.com/2013/09/masscan-entire-internet-in-3-minutes.html

CVE reference : Not defined

Creation date : 2013-10-18

Last modified date : 2013-10-18

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017616
`alert http any any -> $HOME_NET any (msg:"ET SCAN NETWORK Incoming Masscan detected"; flow:established,to_server; content:"masscan/"; depth:8; http_user_agent; reference:url,blog.erratasec.com/2013/10/that-dlink-bug-masscan.html; reference:url,blog.erratasec.com/2013/09/masscan-entire-internet-in-3-minutes.html; classtype:network-scan; sid:2017616; rev:4; metadata:created_at 2013_10_18, updated_at 2013_10_18;)
` 

Name : **NETWORK Incoming Masscan detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,blog.erratasec.com/2013/10/that-dlink-bug-masscan.html|url,blog.erratasec.com/2013/09/masscan-entire-internet-in-3-minutes.html

CVE reference : Not defined

Creation date : 2013-10-18

Last modified date : 2013-10-18

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008416
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Httprint Web Server Fingerprint Scan"; flow:established,to_server; content:"GET"; http_method; content:"/antidisestablishmentarianism"; http_uri; reference:url,www.net-square.com/httprint/; reference:url,www.net-square.com/httprint/httprint_paper.html; reference:url,doc.emergingthreats.net/2008416; classtype:attempted-recon; sid:2008416; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Httprint Web Server Fingerprint Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.net-square.com/httprint/|url,www.net-square.com/httprint/httprint_paper.html|url,doc.emergingthreats.net/2008416

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002677
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nikto Web App Scan in Progress"; flow:to_server,established; content:"(Nikto"; http_user_agent; threshold: type both, count 5, seconds 60, track by_src; reference:url,www.cirt.net/code/nikto.shtml; reference:url,doc.emergingthreats.net/2002677; classtype:web-application-attack; sid:2002677; rev:13; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Nikto Web App Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.cirt.net/code/nikto.shtml|url,doc.emergingthreats.net/2002677

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 13

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009582
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 1024"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:1024; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2009582; classtype:attempted-recon; sid:2009582; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sS window 1024** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009582

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009583
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 3072"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:3072; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2009583; classtype:attempted-recon; sid:2009583; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sS window 3072** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009583

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009584
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 4096"; fragbits:!D; dsize:0; flags:S,12; ack:0; window:4096; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2009584; classtype:attempted-recon; sid:2009584; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -sS window 4096** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009584

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018317
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN NMAP SIP Version Detect OPTIONS Scan"; flow:established,to_server; content:"OPTIONS sip|3A|nm SIP/"; depth:19; classtype:attempted-recon; sid:2018317; rev:1; metadata:created_at 2014_03_25, updated_at 2014_03_25;)
` 

Name : **NMAP SIP Version Detect OPTIONS Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-25

Last modified date : 2014-03-25

Rev version : 1

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018318
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5060:5061 (msg:"ET SCAN NMAP SIP Version Detection Script Activity"; content:"Via|3A| SIP/2.0/TCP nm"; content:"From|3A| <sip|3A|nm@nm"; within:150; fast_pattern; classtype:attempted-recon; sid:2018318; rev:1; metadata:created_at 2014_03_25, updated_at 2014_03_25;)
` 

Name : **NMAP SIP Version Detection Script Activity** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-25

Last modified date : 2014-03-25

Rev version : 1

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003171
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN IBM NSA User Agent"; flow:established,to_server; content:"Network-Services-Auditor"; http_user_agent; threshold: type limit, track by_src,count 1, seconds 60; reference:url,ftp.inf.utfsm.cl/pub/Docs/IBM/Tivoli/pdfs/sg246021.pdf; reference:url,doc.emergingthreats.net/2003171; classtype:attempted-recon; sid:2003171; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IBM NSA User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,ftp.inf.utfsm.cl/pub/Docs/IBM/Tivoli/pdfs/sg246021.pdf|url,doc.emergingthreats.net/2003171

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000545
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sV"; fragbits:!M; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; reference:url,doc.emergingthreats.net/2000545; classtype:attempted-recon; sid:2000545; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **NMAP -f -sV** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2000545

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018800
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Chroot-apache0day Unknown Web Scanner User Agent"; flow:established,to_server; content:"chroot-apach0day"; nocase; http_user_agent; depth:16; reference:url,isc.sans.edu/forums/diary/Interesting+HTTP+User+Agent+chroot-apach0day+/18453; classtype:attempted-recon; sid:2018800; rev:4; metadata:created_at 2014_07_29, updated_at 2014_07_29;)
` 

Name : **Chroot-apache0day Unknown Web Scanner User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,isc.sans.edu/forums/diary/Interesting+HTTP+User+Agent+chroot-apach0day+/18453

CVE reference : Not defined

Creation date : 2014-07-29

Last modified date : 2014-07-29

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016763
`#alert tcp 188.95.234.6 any -> $HOME_NET [22,443] (msg:"ET SCAN Non-Malicious SSH/SSL Scanner on the run"; threshold: type limit, track by_src, seconds 60, count 1; reference:url,pki.net.in.tum.de/node/21; reference:url,isc.sans.edu/diary/SSH%2bscans%2bfrom%2b188.95.234.6/15532; classtype:network-scan; sid:2016763; rev:7; metadata:created_at 2013_04_17, updated_at 2013_04_17;)
` 

Name : **Non-Malicious SSH/SSL Scanner on the run** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,pki.net.in.tum.de/node/21|url,isc.sans.edu/diary/SSH%2bscans%2bfrom%2b188.95.234.6/15532

CVE reference : Not defined

Creation date : 2013-04-17

Last modified date : 2013-04-17

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009038
`alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN SQLNinja MSSQL Version Scan"; flow:to_server,established; content:"?param=a"; content:"if%20not%28substring%28%28select%20%40%40version"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009038; classtype:attempted-recon; sid:2009038; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SQLNinja MSSQL Version Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009038

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009359
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)"; flow:to_server,established; content:"Nmap NSE"; http_user_agent; reference:url,doc.emergingthreats.net/2009359; classtype:web-application-attack; sid:2009359; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Nmap Scripting Engine User-Agent Detected (Nmap NSE)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009359

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009827
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Pavuk User Agent Detected - Website Mirroring Tool for Off-line Analysis"; flow:established,to_server; content:"pavuk"; http_user_agent; nocase; reference:url,pavuk.sourceforge.net/about.html; reference:url,doc.emergingthreats.net/2009827; classtype:attempted-recon; sid:2009827; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Pavuk User Agent Detected - Website Mirroring Tool for Off-line Analysis** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,pavuk.sourceforge.net/about.html|url,doc.emergingthreats.net/2009827

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009882
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Default Mysqloit User Agent Detected - Mysql Injection Takover Tool"; flow:established,to_server; content:"Mysqloit"; http_user_agent; reference:url,code.google.com/p/mysqloit/; classtype:attempted-recon; sid:2009882; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Default Mysqloit User Agent Detected - Mysql Injection Takover Tool** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/mysqloit/

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009883
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible Mysqloit Operating System Fingerprint/SQL Injection Test Scan Detected"; flow:established,to_server; content:"+UNION+select+'BENCHMARK(10000000,SHA1(1))"; http_uri; reference:url,code.google.com/p/mysqloit/; reference:url,doc.emergingthreats.net/2009883; classtype:attempted-recon; sid:2009883; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible Mysqloit Operating System Fingerprint/SQL Injection Test Scan Detected** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/mysqloit/|url,doc.emergingthreats.net/2009883

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010215
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN SQL Injection Attempt (Agent uil2pn)"; flow:to_server,established; content:"uil2pn"; http_user_agent; reference:url,www.prevx.com/filenames/89385984947861762-X1/UIL2PN.EXE.html; reference:url,doc.emergingthreats.net/2010215; classtype:web-application-attack; sid:2010215; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SQL Injection Attempt (Agent uil2pn)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.prevx.com/filenames/89385984947861762-X1/UIL2PN.EXE.html|url,doc.emergingthreats.net/2010215

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 5

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010343
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN pangolin SQL injection tool"; flow:established,to_server; content:"pangolin"; http_user_agent; reference:url,www.lifedork.net/pangolin-best-sql-injection-tool.html; classtype:web-application-activity; sid:2010343; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **pangolin SQL injection tool** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-activity

URL reference : url,www.lifedork.net/pangolin-best-sql-injection-tool.html

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010508
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Springenwerk XSS Scanner User-Agent Detected"; flow:to_server,established; content:"Springenwerk"; http_user_agent; threshold: type limit, count 1, seconds 60, track by_src; reference:url,springenwerk.org/; reference:url,doc.emergingthreats.net/2010508; classtype:attempted-recon; sid:2010508; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Springenwerk XSS Scanner User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,springenwerk.org/|url,doc.emergingthreats.net/2010508

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010956
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Skipfish Web Application Scan Detected (2)"; flow:established,to_server; content:"GET"; http_method; content:".old"; http_uri; content:"Mozilla/5.0 SF/"; http_user_agent; content:"Range|3A| bytes=0-199999"; http_header; reference:url,isc.sans.org/diary.html?storyid=8467; reference:url,code.google.com/p/skipfish/; reference:url,doc.emergingthreats.net/2010956; classtype:attempted-recon; sid:2010956; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Skipfish Web Application Scan Detected (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,isc.sans.org/diary.html?storyid=8467|url,code.google.com/p/skipfish/|url,doc.emergingthreats.net/2010956

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010954
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN crimscanner User-Agent detected"; flow:established,to_server; content:"GET"; http_method; content:"crimscanner/"; nocase; http_user_agent; reference:url,doc.emergingthreats.net/2010954; classtype:network-scan; sid:2010954; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **crimscanner User-Agent detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,doc.emergingthreats.net/2010954

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011088
`alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN Possible DavTest WebDav Vulnerability Scanner Initial Check Detected"; flow:established,to_server; content:"PROPFIND "; depth:9; content:"D|3A|propfind xmlns|3A|D=|22|DAV|3A 22|><D|3A|allprop/></D|3A|propfind>"; distance:0; reference:url,www.darknet.org.uk/2010/04/davtest-webdav-vulerability-scanning-scanner-tool/; reference:url,code.google.com/p/davtest/; reference:url,doc.emergingthreats.net/2011088; classtype:attempted-recon; sid:2011088; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible DavTest WebDav Vulnerability Scanner Initial Check Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.darknet.org.uk/2010/04/davtest-webdav-vulerability-scanning-scanner-tool/|url,code.google.com/p/davtest/|url,doc.emergingthreats.net/2011088

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011389
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET SCAN w3af Scan Remote File Include Retrieval"; flow:established,to_server; content:"/w3af/remoteFileInclude.html"; http_uri; nocase; content:"Host|3A| w3af.sourceforge.net"; http_header; nocase; reference:url,w3af.sourceforge.net; classtype:web-application-activity; sid:2011389; rev:5; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_09_27, updated_at 2016_07_01;)
` 

Name : **w3af Scan Remote File Include Retrieval** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-activity

URL reference : url,w3af.sourceforge.net

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2016-07-01

Rev version : 5

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011720
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible WafWoof Web Application Firewall Detection Scan"; flow:established,to_server; content:"GET"; http_method; content:"/<invalid>hello.html"; http_uri; reference:url,code.google.com/p/waffit/; reference:url,doc.emergingthreats.net/2011720; classtype:attempted-recon; sid:2011720; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible WafWoof Web Application Firewall Detection Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/waffit/|url,doc.emergingthreats.net/2011720

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012937
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Internal Dummy Connection User-Agent Inbound"; flow:established,to_server; content:"(internal dummy connection)"; http_user_agent; classtype:trojan-activity; sid:2012937; rev:3; metadata:created_at 2011_06_06, updated_at 2011_06_06;)
` 

Name : **Internal Dummy Connection User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-06

Last modified date : 2011-06-06

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011390
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Nikto Scan Remote File Include Retrieval"; flow:established,to_server; content:"/rfiinc.txt"; http_uri; content:"Host|3A| cirt.net|0d 0a|"; http_header; nocase; reference:url,cirt.net/nikto2; classtype:web-application-activity; sid:2011390; rev:4; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_09_27, updated_at 2016_07_01;)
` 

Name : **Nikto Scan Remote File Include Retrieval** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-activity

URL reference : url,cirt.net/nikto2

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2016-07-01

Rev version : 4

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011367
`#alert tcp any any -> any any (msg:"ET SCAN Malformed Packet SYN FIN"; flags:SF; classtype:bad-unknown; sid:2011367; rev:2; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Malformed Packet SYN FIN** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011368
`#alert tcp any any -> any any (msg:"ET SCAN Malformed Packet SYN RST"; flags:SR; classtype:bad-unknown; sid:2011368; rev:2; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Malformed Packet SYN RST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016033
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Simple Slowloris Flooder"; flow:established,to_server; content:"POST"; http_method; content:"Content-length|3A| 5235|0D 0A|"; http_header; content:!"User-Agent|3a|"; http_header; threshold:type limit, track by_src, count 1, seconds 300; reference:url,www.imperva.com/docs/HII_Denial_of_Service_Attacks-Trends_Techniques_and_Technologies.pdf; classtype:web-application-attack; sid:2016033; rev:4; metadata:created_at 2012_12_13, updated_at 2012_12_13;)
` 

Name : **Simple Slowloris Flooder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.imperva.com/docs/HII_Denial_of_Service_Attacks-Trends_Techniques_and_Technologies.pdf

CVE reference : Not defined

Creation date : 2012-12-13

Last modified date : 2012-12-13

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019963
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Acunetix Accept HTTP Header detected scan in progress"; flow:established,to_server; content:"Accept|3a 20|acunetix"; http_header; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.acunetix.com/; classtype:attempted-recon; sid:2019963; rev:2; metadata:created_at 2014_12_17, updated_at 2014_12_17;)
` 

Name : **Acunetix Accept HTTP Header detected scan in progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.acunetix.com/

CVE reference : Not defined

Creation date : 2014-12-17

Last modified date : 2014-12-17

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020853
`alert tcp any any -> $HOME_NET 1720 (msg:"ET SCAN H.323 Scanning device"; flow:established,to_server; content:"|40 04 00 63 00 69 00 73 00 63 00 6f|"; fast_pattern; offset:55; depth:12; threshold: type limit, track by_src, count 1, seconds 60; reference:url,videonationsltd.co.uk/2014/11/h-323-cisco-spam-calls/; classtype:network-scan; sid:2020853; rev:2; metadata:created_at 2015_04_07, updated_at 2015_04_07;)
` 

Name : **H.323 Scanning device** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,videonationsltd.co.uk/2014/11/h-323-cisco-spam-calls/

CVE reference : Not defined

Creation date : 2015-04-07

Last modified date : 2015-04-07

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010686
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ICMP =XXXXXXXX Likely Precursor to Scan"; itype:8; icode:0; content:"=XXXXXXXX"; reference:url,doc.emergingthreats.net/2010686; classtype:network-scan; sid:2010686; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICMP =XXXXXXXX Likely Precursor to Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,doc.emergingthreats.net/2010686

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006546
`alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack"; flow:established,to_server; content:"SSH-"; content:"libssh"; within:20; threshold: type both, count 5, seconds 30, track by_src; reference:url,doc.emergingthreats.net/2006546; classtype:attempted-admin; sid:2006546; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **LibSSH Based Frequent SSH Connections Likely BruteForce Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2006546

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002383
`alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (msg:"ET SCAN Potential FTP Brute-Force attempt response"; flow:from_server,established; dsize:<100; content:"530 "; depth:4; pcre:"/530\s+(Login|User|Failed|Not)/smi"; threshold: type threshold, track by_dst, count 5, seconds 300; reference:url,doc.emergingthreats.net/2002383; classtype:unsuccessful-user; sid:2002383; rev:12; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential FTP Brute-Force attempt response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : url,doc.emergingthreats.net/2002383

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 12

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021023
`alert tcp any any -> $HOME_NET any (msg:"ET SCAN Nmap NSE Heartbleed Request"; flow:established,to_server; content:"|18 03|"; depth:2; byte_test:1,<,4,2; content:"|01|"; offset:5; depth:1; byte_test:2,>,2,3; byte_test:2,>,200,6; content:"|40 00|Nmap ssl-heartbleed"; fast_pattern:2,19; classtype:attempted-recon; sid:2021023; rev:1; metadata:created_at 2015_04_28, updated_at 2015_04_28;)
` 

Name : **Nmap NSE Heartbleed Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-04-28

Last modified date : 2015-04-28

Rev version : 1

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021024
`alert tcp $HOME_NET any -> any any (msg:"ET SCAN Nmap NSE Heartbleed Response"; flow:established,from_server; content:"|18 03|"; depth:2; byte_test:1,<,4,2; byte_test:2,>,200,3; content:"|40 00|Nmap ssl-heartbleed"; fast_pattern:2,19; classtype:attempted-recon; sid:2021024; rev:1; metadata:created_at 2015_04_28, updated_at 2015_04_28;)
` 

Name : **Nmap NSE Heartbleed Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-04-28

Last modified date : 2015-04-28

Rev version : 1

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011034
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN HTTP OPTIONS invalid method case"; flow:established,to_server; content:"options"; http_method; nocase; content:!"OPTIONS"; http_method; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html; reference:url,doc.emergingthreats.net/2011034; classtype:bad-unknown; sid:2011034; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HTTP OPTIONS invalid method case** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec9.html|url,doc.emergingthreats.net/2011034

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001219
`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; reference:url,doc.emergingthreats.net/2001219; classtype:attempted-recon; sid:2001219; rev:20; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential SSH Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,en.wikipedia.org/wiki/Brute_force_attack|url,doc.emergingthreats.net/2001219

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 20

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002910
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential VNC Scan 5800-5820** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2002910

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002911
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5900:5920 (msg:"ET SCAN Potential VNC Scan 5900-5920"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002911; classtype:attempted-recon; sid:2002911; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential VNC Scan 5900-5920** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2002911

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002992
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"ET SCAN Rapid POP3 Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 120; reference:url,doc.emergingthreats.net/2002992; classtype:misc-activity; sid:2002992; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rapid POP3 Connections - Possible Brute Force Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002992

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002993
`alert tcp $EXTERNAL_NET any -> $HOME_NET 995 (msg:"ET SCAN Rapid POP3S Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 120; reference:url,doc.emergingthreats.net/2002993; classtype:misc-activity; sid:2002993; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rapid POP3S Connections - Possible Brute Force Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002993

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002994
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"ET SCAN Rapid IMAP Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; reference:url,doc.emergingthreats.net/2002994; classtype:misc-activity; sid:2002994; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rapid IMAP Connections - Possible Brute Force Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002994

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002995
`alert tcp $EXTERNAL_NET any -> $HOME_NET 993 (msg:"ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; reference:url,doc.emergingthreats.net/2002995; classtype:misc-activity; sid:2002995; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rapid IMAPS Connections - Possible Brute Force Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002995

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003068
`alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:"ET SCAN Potential SSH Scan OUTBOUND"; flow:to_server; flags:S,12; threshold: type threshold, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; reference:url,doc.emergingthreats.net/2003068; classtype:attempted-recon; sid:2003068; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential SSH Scan OUTBOUND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,en.wikipedia.org/wiki/Brute_force_attack|url,doc.emergingthreats.net/2003068

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014869
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Arachni Scanner Web Scan"; flow:established,to_server; content:"Arachni/"; http_header; pcre:"/User-Agent\x3a[^\r\n]+Arachni\/v?\d\.\d\.\d$/iH"; threshold: type limit, track by_src, count 1, seconds 300; reference:url,arachni-scanner.com; reference:url,github.com/Zapotek/arachni; classtype:attempted-recon; sid:2014869; rev:5; metadata:created_at 2012_06_07, updated_at 2012_06_07;)
` 

Name : **Arachni Scanner Web Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,arachni-scanner.com|url,github.com/Zapotek/arachni

CVE reference : Not defined

Creation date : 2012-06-07

Last modified date : 2012-06-07

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022240
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible Scanning for Vulnerable JBoss"; flow:established,to_server; content:"POST"; http_method; content:"/invoker/"; http_uri; depth:9; content:"servlet/"; http_uri; content:"Content-Type|3a 20|application/x-java-serialized-object|3b 0d 0a|"; http_header; content:"org.jboss.invocation.MarshalledValue"; http_client_body; reference:url,blog.imperva.com/2015/12/zero-day-attack-strikes-again-java-zero-day-vulnerability-cve-2015-4852-tracked-by-imperva.html; classtype:web-application-attack; sid:2022240; rev:2; metadata:created_at 2015_12_08, updated_at 2015_12_08;)
` 

Name : **Possible Scanning for Vulnerable JBoss** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.imperva.com/2015/12/zero-day-attack-strikes-again-java-zero-day-vulnerability-cve-2015-4852-tracked-by-imperva.html

CVE reference : Not defined

Creation date : 2015-12-08

Last modified date : 2015-12-08

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018755
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET SCAN Possible WordPress xmlrpc.php BruteForce in Progress - Response"; flow:established,from_server; flowbits:isset,ET.XMLRPC.PHP; file_data; content:"<name>faultCode</name>"; content:"<int>403</int>"; content:"<string>Incorrect username or password.</string>"; threshold:type both, track by_src, count 5, seconds 120; reference:url,isc.sans.edu/diary/+WordPress+brute+force+attack+via+wp.getUsersBlogs/18427; classtype:attempted-admin; sid:2018755; rev:5; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2014_07_23, updated_at 2016_07_01;)
` 

Name : **Possible WordPress xmlrpc.php BruteForce in Progress - Response** 

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

Alert Classtype : attempted-admin

URL reference : url,isc.sans.edu/diary/+WordPress+brute+force+attack+via+wp.getUsersBlogs/18427

CVE reference : Not defined

Creation date : 2014-07-23

Last modified date : 2016-07-01

Rev version : 5

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022581
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN MySQL Malicious Scanning 3"; flow:to_server; content:"|00 03|"; offset:3; depth:2; content:"select unhex("; fast_pattern; distance:0; content:"into dumpfile|20 27|"; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781; classtype:bad-unknown; sid:2022581; rev:1; metadata:created_at 2016_03_01, updated_at 2016_03_01;)
` 

Name : **MySQL Malicious Scanning 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781

CVE reference : Not defined

Creation date : 2016-03-01

Last modified date : 2016-03-01

Rev version : 1

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001553
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 443 (msg:"ET SCAN Possible SSL Brute Force attack or Site Crawl"; flow: established,to_server; flags: S; threshold: type threshold, track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2001553; classtype:attempted-dos; sid:2001553; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible SSL Brute Force attack or Site Crawl** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2001553

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001904
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"ET SCAN Behavioral Unusually fast inbound Telnet Connections, Potential Scan or Brute Force"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; reference:url,www.rapid7.com/nexpose-faq-answer2.htm; reference:url,doc.emergingthreats.net/2001904; classtype:misc-activity; sid:2001904; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Behavioral Unusually fast inbound Telnet Connections, Potential Scan or Brute Force** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.rapid7.com/nexpose-faq-answer2.htm|url,doc.emergingthreats.net/2001904

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002973
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 3127 (msg:"ET SCAN Behavioral Unusual Port 3127 traffic, Potential Scan or Backdoor"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 10 , seconds 60; reference:url,doc.emergingthreats.net/2002973; classtype:misc-activity; sid:2002973; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Behavioral Unusual Port 3127 traffic, Potential Scan or Backdoor** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002973

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008230
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 23 (msg:"ET SCAN Behavioral Unusually fast outbound Telnet Connections, Potential Scan or Brute Force"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 30, seconds 60; reference:url,www.rapid7.com/nexpose-faq-answer2.htm; reference:url,doc.emergingthreats.net/2008230; classtype:misc-activity; sid:2008230; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Behavioral Unusually fast outbound Telnet Connections, Potential Scan or Brute Force** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.rapid7.com/nexpose-faq-answer2.htm|url,doc.emergingthreats.net/2008230

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023510
`alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (msg:"ET SCAN Redis SSH Key Overwrite Probing"; flow:to_server,established; content:"*"; depth:1; content:"config"; content:"set"; distance:0; content:"dir"; distance:0; content:"/.ssh"; distance:0; isdataat:!5,relative; reference:url,antirez.com/news/96; classtype:misc-attack; sid:2023510; rev:2; metadata:attack_target Client_Endpoint, deployment Datacenter, tag SCAN_Redis_SSH, signature_severity Minor, created_at 2016_07_07, performance_impact Low, updated_at 2016_11_15;)
` 

Name : **Redis SSH Key Overwrite Probing** 

Attack target : Client_Endpoint

Description : This signature matches on network traffic to the Redis Server when a network SCAN is in progress to determine which version is running. There could be a weak security in Redis server as well as misconfigured servers that may have running the redis server with elevated privileges. Exploited servers are known to participate in DDoS botnets. 

An attacker has attempted to map a network, running applications, or services available. This is often benign, but can frequently indicate a more concerted attack is in progress.

Tags : SCAN_Redis_SSH

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,antirez.com/news/96

CVE reference : Not defined

Creation date : 2016-07-07

Last modified date : 2016-11-15

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023753
`alert tcp $EXTERNAL_NET any -> $HOME_NET !3389 (msg:"ET SCAN MS Terminal Server Traffic on Non-standard Port"; flow:to_server,established; content:"|03 00 00|"; depth:3; content:"|e0 00 00 00 00 00|"; offset:5; depth:6; content:"Cookie|3a| mstshash="; fast_pattern; classtype:attempted-recon; sid:2023753; rev:2; metadata:affected_product Microsoft_Terminal_Server_RDP, attack_target Server, deployment Perimeter, signature_severity Major, created_at 2017_01_23, performance_impact Low, updated_at 2017_02_23;)
` 

Name : **MS Terminal Server Traffic on Non-standard Port** 

Attack target : Server

Description : This signatures matches an initial RDP setup request on non standard port.

Tags : Not defined

Affected products : Microsoft_Terminal_Server_RDP

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-01-23

Last modified date : 2017-02-23

Rev version : 2

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2010681
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ICMP Delphi Likely Precursor to Scan"; itype:8; icode:0; content:"Pinging from Delphi code written"; metadata: former_category SCAN; reference:url,www.koders.com/delphi/fid942A4EAF946B244BD3CD9BC83FEAAC35BA1F38AB.aspx; reference:url,doc.emergingthreats.net/2010681; classtype:misc-activity; sid:2010681; rev:3; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **ICMP Delphi Likely Precursor to Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.koders.com/delphi/fid942A4EAF946B244BD3CD9BC83FEAAC35BA1F38AB.aspx|url,doc.emergingthreats.net/2010681

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010494
`alert tcp $HOME_NET 3306 -> $EXTERNAL_NET any (msg:"ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt"; flow:from_server,established; dsize:<251; byte_test:1,<,0xfb,0,little; content:"|ff 15 04 23 32 38 30 30 30|"; offset:4; threshold: type threshold, track by_src, count 5, seconds 120; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2010494; classtype:attempted-recon; sid:2010494; rev:4; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Multiple MySQL Login Failures Possible Brute Force Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010494

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001569
`alert tcp $HOME_NET any -> any 445 (msg:"ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001569; classtype:misc-activity; sid:2001569; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 445 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001569

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001579
`alert tcp $HOME_NET any -> any 139 (msg:"ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001579; classtype:misc-activity; sid:2001579; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 139 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001579

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001580
`alert tcp $HOME_NET any -> any 137 (msg:"ET SCAN Behavioral Unusual Port 137 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001580; classtype:misc-activity; sid:2001580; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 137 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001580

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001581
`alert tcp $HOME_NET any -> any 135 (msg:"ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001581; classtype:misc-activity; sid:2001581; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 135 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001581

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001582
`alert tcp $HOME_NET any -> any 1434 (msg:"ET SCAN Behavioral Unusual Port 1434 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 40 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001582; classtype:misc-activity; sid:2001582; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 1434 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001582

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001583
`alert tcp $HOME_NET any -> any 1433 (msg:"ET SCAN Behavioral Unusual Port 1433 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 40 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001583; classtype:misc-activity; sid:2001583; rev:16; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusual Port 1433 traffic Potential Scan or Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2001583

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 16

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001972
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound)"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 20, seconds 360; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001972; classtype:network-scan; sid:2001972; rev:20; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,doc.emergingthreats.net/2001972

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 20

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010087
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Suspicious User-Agent Containing SQL Inject/ion Likely SQL Injection Scanner"; flow:established,to_server; content:"SQL"; nocase; depth:200; http_user_agent; content:"Inject"; nocase; distance:0; http_user_agent; metadata: former_category HUNTING; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,doc.emergingthreats.net/2010087; classtype:attempted-recon; sid:2010087; rev:7; metadata:affected_product Web_Server_Applications, affected_product Any, attack_target Client_Endpoint, deployment Perimeter, deployment Datacenter, tag SQL_Injection, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Suspicious User-Agent Containing SQL Inject/ion Likely SQL Injection Scanner** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : SQL_Injection, User_Agent

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,www.owasp.org/index.php/SQL_Injection|url,doc.emergingthreats.net/2010087

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 7

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010088
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Suspicious User-Agent Containing Web Scan/er Likely Web Scanner"; flow:established,to_server; content:"web"; nocase; depth:200; http_user_agent; content:"scan"; nocase; distance:0; http_user_agent; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010088; classtype:attempted-recon; sid:2010088; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Suspicious User-Agent Containing Web Scan/er Likely Web Scanner** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010088

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 6

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010089
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Suspicious User-Agent Containing Security Scan/ner Likely Scan"; flow:established,to_server; content:"security"; nocase; http_user_agent; content:"scan"; nocase; distance:0; http_user_agent; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010089; classtype:attempted-recon; sid:2010089; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Suspicious User-Agent Containing Security Scan/ner Likely Scan** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010089

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 6

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010641
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ICMP @hello request Likely Precursor to Scan"; itype:8; icode:0; content:"@hello ???"; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2010641; classtype:misc-activity; sid:2010641; rev:3; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **ICMP @hello request Likely Precursor to Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2010641

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013479
`alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:"ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Outbound)"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 20, seconds 360; metadata: former_category SCAN; reference:url,threatpost.com/en_us/blogs/new-worm-morto-using-rdp-infect-windows-pcs-082811; classtype:misc-activity; sid:2013479; rev:5; metadata:created_at 2011_08_29, updated_at 2017_05_11;)
` 

Name : **Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Outbound)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,threatpost.com/en_us/blogs/new-worm-morto-using-rdp-infect-windows-pcs-082811

CVE reference : Not defined

Creation date : 2011-08-29

Last modified date : 2017-05-11

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024364
`alert http $HOME_NET any -> any any (msg:"ET SCAN Possible Nmap User-Agent Observed"; flow:to_server,established; content:"|20|Nmap"; http_user_agent; fast_pattern; metadata: former_category SCAN; classtype:web-application-attack; sid:2024364; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, signature_severity Informational, created_at 2017_06_08, performance_impact Low, updated_at 2017_06_13;)
` 

Name : **Possible Nmap User-Agent Observed** 

Attack target : Client_and_Server

Description : This will alert on nmap present in a User-Agent string, which may be indicative of scanning activity.

Tags : Not defined

Affected products : Any

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-06-08

Last modified date : 2017-06-13

Rev version : 3

Category : SCAN

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2024843
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN struts-pwn User-Agent"; flow:established,to_server; content:"struts-pwn"; depth:10; http_user_agent; fast_pattern;metadata:affected_product Apache_Struts2, attack_target Web_Server, deployment Perimeter, signature_severity Critical; metadata: former_category SCAN; reference:url,github.com/mazen160/struts-pwn_CVE-2017-9805/blob/master/struts-pwn.py; reference:cve,2017-9805; reference:url,paladion.net/paladion-cyber-labs-discovers-a-new-ransomware/; classtype:attempted-user; sid:2024843; rev:2; metadata:affected_product Apache_Struts2, attack_target Web_Server, deployment Datacenter, signature_severity Minor, created_at 2017_10_16, performance_impact Moderate, updated_at 2017_10_16;)
` 

Name : **struts-pwn User-Agent** 

Attack target : Web_Server

Description : Alerts on inbound scan from struts-pwn tool

Tags : Not defined

Affected products : Apache_Struts2

Alert Classtype : attempted-user

URL reference : url,github.com/mazen160/struts-pwn_CVE-2017-9805/blob/master/struts-pwn.py|cve,2017-9805|url,paladion.net/paladion-cyber-labs-discovers-a-new-ransomware/

CVE reference : Not defined

Creation date : 2017-10-16

Last modified date : 2017-10-16

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2012726
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN OpenVAS User-Agent Inbound"; flow:established,to_server; content:"OpenVAS"; http_user_agent; reference:url,openvas.org; classtype:attempted-recon; sid:2012726; rev:5; metadata:created_at 2011_04_26, updated_at 2011_04_26;)
` 

Name : **OpenVAS User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,openvas.org

CVE reference : Not defined

Creation date : 2011-04-26

Last modified date : 2011-04-26

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008186
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN DirBuster Web App Scan in Progress"; flow:to_server,established; content:"DirBuster"; depth:9; http_user_agent; reference:url,owasp.org; reference:url,doc.emergingthreats.net/2008186; classtype:web-application-attack; sid:2008186; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **DirBuster Web App Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,owasp.org|url,doc.emergingthreats.net/2008186

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008538
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Sqlmap SQL Injection Scan"; flow:to_server,established; content:"sqlmap"; depth:6; http_user_agent; threshold: type limit, count 2, seconds 40, track by_src; reference:url,sqlmap.sourceforge.net; reference:url,doc.emergingthreats.net/2008538; classtype:attempted-recon; sid:2008538; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Sqlmap SQL Injection Scan** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,sqlmap.sourceforge.net|url,doc.emergingthreats.net/2008538

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 7

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019876
`alert ssh $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN SSH BruteForce Tool with fake PUTTY version"; flow:established,to_server; ssh_proto; content:"PUTTY"; threshold: type limit, track by_src, count 1, seconds 30; metadata: former_category SCAN; classtype:network-scan; sid:2019876; rev:6; metadata:created_at 2014_12_05, updated_at 2017_12_01;)
` 

Name : **SSH BruteForce Tool with fake PUTTY version** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-05

Last modified date : 2017-12-01

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010939
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"ET SCAN Suspicious inbound to PostgreSQL port 5432"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010939; classtype:bad-unknown; sid:2010939; rev:3; metadata:created_at 2010_07_30, updated_at 2018_03_27;)
` 

Name : **Suspicious inbound to PostgreSQL port 5432** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010939

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-03-27

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010938
`alert tcp $EXTERNAL_NET any -> $HOME_NET 4333 (msg:"ET SCAN Suspicious inbound to mSQL port 4333"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010938; classtype:bad-unknown; sid:2010938; rev:3; metadata:created_at 2010_07_30, updated_at 2018_03_27;)
` 

Name : **Suspicious inbound to mSQL port 4333** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010938

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-03-27

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010937
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN Suspicious inbound to mySQL port 3306"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010937; classtype:bad-unknown; sid:2010937; rev:3; metadata:created_at 2010_07_30, updated_at 2018_03_27;)
` 

Name : **Suspicious inbound to mySQL port 3306** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010937

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-03-27

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010936
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1521 (msg:"ET SCAN Suspicious inbound to Oracle SQL port 1521"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010936; classtype:bad-unknown; sid:2010936; rev:3; metadata:created_at 2010_07_30, updated_at 2018_03_27;)
` 

Name : **Suspicious inbound to Oracle SQL port 1521** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010936

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-03-27

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010935
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1433 (msg:"ET SCAN Suspicious inbound to MSSQL port 1433"; flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2010935; classtype:bad-unknown; sid:2010935; rev:3; metadata:created_at 2010_07_30, updated_at 2018_03_27;)
` 

Name : **Suspicious inbound to MSSQL port 1433** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010935

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-03-27

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025461
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NYU Internet Census UA Inbound"; content:"NYU Internet Census"; http_user_agent; depth:19; metadata: former_category SCAN; reference:url,scan.lol; classtype:network-scan; sid:2025461; rev:2; metadata:deployment Perimeter, deployment Datacenter, signature_severity Informational, created_at 2018_04_03, updated_at 2018_04_03;)
` 

Name : **NYU Internet Census UA Inbound** 

Attack target : Not defined

Description : alerts on internet census project UA string "User-Agent: NYU Internet Census (https://scan.lol; research@scan.lol)"

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,scan.lol

CVE reference : Not defined

Creation date : 2018-04-03

Last modified date : 2018-04-03

Rev version : 2

Category : SCAN

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003466
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN PHP Attack Tool Morfeus F Scanner"; flow:established,to_server; content:"Morfeus"; nocase; http_user_agent; depth:7; metadata: former_category WEB_SERVER; reference:url,www.webmasterworld.com/search_engine_spiders/3227720.htm; reference:url,doc.emergingthreats.net/2003466; classtype:web-application-attack; sid:2003466; rev:15; metadata:created_at 2010_07_30, updated_at 2018_04_17;)
` 

Name : **PHP Attack Tool Morfeus F Scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.webmasterworld.com/search_engine_spiders/3227720.htm|url,doc.emergingthreats.net/2003466

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-04-17

Rev version : 15

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025760
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN HP Enterprise VAN SDN Controller"; flow:established,to_server; content:"/sdn/ui/app/rs/hpws/config"; http_uri; isdataat:!1,relative; content:"X-Auth-Token|3a| AuroraSdnToken"; http_header; fast_pattern; metadata: former_category SCAN; reference:url,exploit-db.com/exploits/44951/; classtype:attempted-recon; sid:2025760; rev:1; metadata:attack_target Networking_Equipment, deployment Datacenter, signature_severity Major, created_at 2018_06_28, updated_at 2019_09_28;)
` 

Name : **HP Enterprise VAN SDN Controller** 

Attack target : Networking_Equipment

Description : This signature detects an attempt to exploit the authentication bypass vulnerability to install malicious code in HP Enterprise VAN SDN Controller

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,exploit-db.com/exploits/44951/

CVE reference : Not defined

Creation date : 2018-06-28

Last modified date : 2019-09-28

Rev version : 2

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025780
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ntop-ng Authentication Bypass via Session ID Guessing"; flow:established,to_server; content:"/lua/network_load.lua"; http_uri; fast_pattern; content:"session="; http_cookie; content:"user="; http_cookie; threshold: type threshold, track by_dst, count 255, seconds 10; metadata: former_category SCAN; reference:cve,2018-12520; reference:url,exploit-db.com/exploits/44973/; classtype:attempted-recon; sid:2025780; rev:2; metadata:attack_target Server, deployment Datacenter, signature_severity Critical, created_at 2018_07_03, performance_impact Low, updated_at 2018_07_18;)
` 

Name : **ntop-ng Authentication Bypass via Session ID Guessing** 

Attack target : Server

Description : This signature will detect an attempt to guess the session ID to Bypass Authentication in ntop-ng.

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,2018-12520|url,exploit-db.com/exploits/44973/

CVE reference : Not defined

Creation date : 2018-07-03

Last modified date : 2018-07-18

Rev version : 2

Category : SCAN

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025822
`alert udp any any -> $HOME_NET 4070 (msg:"ET SCAN HID VertX and Edge door controllers discover"; dsize:<45; content:"discover|3b|013|3b|"; metadata: former_category SCAN; reference:url,exploit-db.com/exploits/44992/; classtype:attempted-recon; sid:2025822; rev:2; metadata:attack_target IoT, deployment Datacenter, created_at 2018_07_10, updated_at 2018_07_18;)
` 

Name : **HID VertX and Edge door controllers discover** 

Attack target : IoT

Description : This signature will detect an attempt to exploit a Remote Command Execution in  HID VertX and Edge door controllers

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,exploit-db.com/exploits/44992/

CVE reference : Not defined

Creation date : 2018-07-10

Last modified date : 2018-07-18

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026008
`alert http any any -> $HOME_NET any (msg:"ET SCAN Geutebrueck re_porter 7.8.974.20 Information Disclosure"; flow:established,to_server; content:"GET"; http_method; content:"/statistics/gscsetup.xml"; http_uri; metadata: former_category SCAN; reference:cve,2018-15534; reference:url,exploit-db.com/exploits/45240/; classtype:attempted-recon; sid:2026008; rev:1; metadata:attack_target IoT, deployment Datacenter, signature_severity Major, created_at 2018_08_22, performance_impact Low, updated_at 2018_08_22;)
` 

Name : **Geutebrueck re_porter 7.8.974.20 Information Disclosure** 

Attack target : IoT

Description : This signature will detect an attempt to retrieve configuration file from Geutebrueck re_porter 7.8.974.20

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,2018-15534|url,exploit-db.com/exploits/45240/

CVE reference : Not defined

Creation date : 2018-08-22

Last modified date : 2018-08-22

Rev version : 1

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026015
`alert http any any -> $HOME_NET any (msg:"ET SCAN Hikvision IP Camera 5.4.0 Information Disclosure"; flow:established,to_server; content:"GET"; http_method; content:"/System/configurationFile?auth=YWRtaW46MTEK"; http_uri; metadata: former_category SCAN; reference:url,exploit-db.com/exploits/45231/; classtype:attempted-recon; sid:2026015; rev:1; metadata:attack_target IoT, deployment Datacenter, signature_severity Major, created_at 2018_08_22, performance_impact Low, updated_at 2018_08_22;)
` 

Name : **Hikvision IP Camera 5.4.0 Information Disclosure** 

Attack target : IoT

Description : This signature will detect an attempt to retrieve configuration file from Hikvision IP Camera 5.4.0

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,exploit-db.com/exploits/45231/

CVE reference : Not defined

Creation date : 2018-08-22

Last modified date : 2018-08-22

Rev version : 1

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026464
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Hello Peppa! Scan Activity"; flow:established,to_server; content:"POST"; http_method; content:".php"; http_uri; content:"=die(|27|Hello, Peppa!|27|"; http_client_body; fast_pattern; metadata: former_category SCAN; reference:url,isc.sans.edu/diary/rss/23860; classtype:attempted-recon; sid:2026464; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_10_10, malware_family Hello_Peppa, performance_impact Moderate, updated_at 2018_10_10;)
` 

Name : **Hello Peppa! Scan Activity** 

Attack target : Client_Endpoint

Description : This will alert on a POST inbound, typically on port 80.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-recon

URL reference : url,isc.sans.edu/diary/rss/23860

CVE reference : Not defined

Creation date : 2018-10-10

Last modified date : 2018-10-10

Rev version : 2

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Hello Peppa

Type : SID

Performance Impact : Moderate

# 2026463
`alert smtp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN StarDotStar HELO, suspected AUTH LOGIN botnet"; flow:established,to_server; content:"HELO|20 2a 2e 2a 0d 0a|"; depth:11; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2026463; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_10_09, updated_at 2018_10_12;)
` 

Name : **StarDotStar HELO, suspected AUTH LOGIN botnet** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-09

Last modified date : 2018-10-12

Rev version : 3

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011914
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN DirBuster Scan in Progress"; flow:established,to_server; content:"/thereIsNoWayThat-You-CanBeThere"; nocase; http_uri; threshold: type limit, track by_src,count 1, seconds 60; reference:url,www.owasp.org/index.php/Category%3aOWASP_DirBuster_Project; classtype:attempted-recon; sid:2011914; rev:2; metadata:created_at 2010_11_09, updated_at 2019_09_26;)
` 

Name : **DirBuster Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.owasp.org/index.php/Category%3aOWASP_DirBuster_Project

CVE reference : Not defined

Creation date : 2010-11-09

Last modified date : 2019-09-26

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011974
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Metasploit WMAP GET len 0 and type"; flow:established,to_server; content:"GET"; http_method; content:"|0d 0a|Content-Type|3A| text/plain|0d 0a|Content-Length|3A| 0|0d 0a|"; http_header; threshold: type limit, track by_src,count 1,seconds 60; classtype:attempted-recon; sid:2011974; rev:4; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_11_24, updated_at 2019_09_26;)
` 

Name : **Metasploit WMAP GET len 0 and type** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-11-24

Last modified date : 2019-09-26

Rev version : 4

Category : SCAN

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012077
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Goatzapszu Header from unknown Scanning Tool"; flow:established,to_server; content:"Goatzapszu|3a|"; nocase; http_header; classtype:attempted-recon; sid:2012077; rev:3; metadata:created_at 2010_12_18, updated_at 2019_09_26;)
` 

Name : **Goatzapszu Header from unknown Scanning Tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-12-18

Last modified date : 2019-09-26

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101102
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SCAN nessus 1.X 404 probe"; flow:to_server,established; content:"/nessus_is_probing_you_"; http_uri; reference:arachnids,301; classtype:web-application-attack; sid:2101102; rev:11; metadata:created_at 2010_09_23, updated_at 2019_09_26;)
` 

Name : **nessus 1.X 404 probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : arachnids,301

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-09-26

Rev version : 11

Category : SCAN

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011887
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Medusa User-Agent"; flow: established,to_server; content:"User-Agent|3A| Teh Forest Lobster"; fast_pattern:10,20; nocase; http_header; threshold: type limit, track by_src,count 1, seconds 60; reference:url,www.foofus.net/~jmk/medusa/medusa.html; classtype:attempted-recon; sid:2011887; rev:3; metadata:created_at 2010_10_31, updated_at 2019_09_26;)
` 

Name : **Medusa User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.foofus.net/~jmk/medusa/medusa.html

CVE reference : Not defined

Creation date : 2010-10-31

Last modified date : 2019-09-26

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011915
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN DotDotPwn User-Agent"; flow:established,to_server; content:"User-Agent|3A| DotDotPwn"; nocase; http_header; threshold:type limit, track by_src,count 1, seconds 60; reference:url,dotdotpwn.sectester.net; classtype:attempted-recon; sid:2011915; rev:3; metadata:created_at 2010_11_09, updated_at 2019_09_26;)
` 

Name : **DotDotPwn User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,dotdotpwn.sectester.net

CVE reference : Not defined

Creation date : 2010-11-09

Last modified date : 2019-09-26

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008092
`alert tcp $HOME_NET any -> $HOME_NET 2555 (msg:"ET SCAN Internal to Internal UPnP Request tcp port 2555"; flow:established,to_server; content:"GET "; depth:4; content:"/upnp/"; nocase; pcre:"/^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{16}\//Ri"; reference:url,www.upnp-hacks.org/upnp.html; reference:url,doc.emergingthreats.net/2008092; classtype:attempted-recon; sid:2008092; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Internal to Internal UPnP Request tcp port 2555** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.upnp-hacks.org/upnp.html|url,doc.emergingthreats.net/2008092

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008093
`alert tcp $EXTERNAL_NET any -> $HOME_NET 2555 (msg:"ET SCAN External to Internal UPnP Request tcp port 2555"; flow:established,to_server; content:"GET "; depth:4; content:"/upnp/"; nocase; pcre:"/^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{16}\//Ri"; reference:url,www.upnp-hacks.org/upnp.html; reference:url,doc.emergingthreats.net/2008093; classtype:attempted-recon; sid:2008093; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **External to Internal UPnP Request tcp port 2555** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.upnp-hacks.org/upnp.html|url,doc.emergingthreats.net/2008093

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008312
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN DEBUG Method Request with Command"; flow:established,to_server; content:"DEBUG "; depth:6; content:"|0d 0a|Command|3a| "; distance:0; reference:url,doc.emergingthreats.net/2008312; classtype:attempted-recon; sid:2008312; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **DEBUG Method Request with Command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2008312

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011721
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible Fast-Track Tool Spidering User-Agent Detected"; flow:established,to_server; content:"|0d 0a|User-Agent|3A| pymills-spider/"; reference:url,www.offensive-security.com/metasploit-unleashed/Fast-Track-Modes; reference:url,doc.emergingthreats.net/2011721; classtype:attempted-recon; sid:2011721; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Fast-Track Tool Spidering User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.offensive-security.com/metasploit-unleashed/Fast-Track-Modes|url,doc.emergingthreats.net/2011721

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009477
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLBrute SQL Scan Detected"; flow:to_server,established; content:"AND not exists (select * from master..sysdatabases)"; offset:60; depth:60; reference:url,www.justinclarke.com/archives/2006/03/sqlbrute.html; reference:url,www.darknet.org.uk/2007/06/sqlbrute-sql-injection-brute-force-tool/; reference:url,doc.emergingthreats.net/2009477; classtype:attempted-recon; sid:2009477; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLBrute SQL Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.justinclarke.com/archives/2006/03/sqlbrute.html|url,www.darknet.org.uk/2007/06/sqlbrute-sql-injection-brute-force-tool/|url,doc.emergingthreats.net/2009477

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009040
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja MSSQL User Scan"; content:"?param=a"; flow:to_server,established; content:"if%20ascii%28substring%28%28select%20system%5Fuser"; distance:2; threshold: type threshold, track by_src, count 20, seconds 10; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009040; classtype:attempted-recon; sid:2009040; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja MSSQL User Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009040

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009041
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja MSSQL Database User Rights Scan"; flow:to_server,established; content:"?param=a"; content:"if%20is%5Fsrvrolemember%28%27sysadmin"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009041; classtype:attempted-recon; sid:2009041; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja MSSQL Database User Rights Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009041

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009042
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja MSSQL Authentication Mode Scan"; flow:to_server,established; content:"?param=a"; content:"if%20not%28%28select%20serverproperty%28%27IsIntegratedSecurityOnly"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009042; classtype:attempted-recon; sid:2009042; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja MSSQL Authentication Mode Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009042

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009043
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja Attempt To Recreate xp_cmdshell Using sp_configure"; flow:to_server,established; content:"?param=a"; content:"exec%20master%2E%2Esp%5Fconfigure%20%27show%20advanced%20options"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009043; classtype:attempted-admin; sid:2009043; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja Attempt To Recreate xp_cmdshell Using sp_configure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009043

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009044
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja Attempt To Create xp_cmdshell Session"; flow:to_server,established; content:"?param=a"; content:"exec%20master%2E%2Exp%5Fcmdshell%20%27cmd%20%2FC%20%25TEMP"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; reference:url,doc.emergingthreats.net/2009044; classtype:attempted-admin; sid:2009044; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja Attempt To Create xp_cmdshell Session** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,sqlninja.sourceforge.net/index.html|url,doc.emergingthreats.net/2009044

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008605
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Stompy Web Application Session Scan"; flow:to_server,established; content:"Session Stomper"; offset:100; depth:25; reference:url,www.darknet.org.uk/2007/03/stompy-the-web-application-session-analyzer-tool/; reference:url,doc.emergingthreats.net/2008605; classtype:attempted-recon; sid:2008605; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Stompy Web Application Session Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.darknet.org.uk/2007/03/stompy-the-web-application-session-analyzer-tool/|url,doc.emergingthreats.net/2008605

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011027
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN w3af Scan In Progress ARGENTINA Req Method"; flow:to_server,established; content:"ARGENTINA "; depth:10; reference:url,w3af.sourceforge.net; reference:url,doc.emergingthreats.net/2011027; classtype:attempted-recon; sid:2011027; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **w3af Scan In Progress ARGENTINA Req Method** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,w3af.sourceforge.net|url,doc.emergingthreats.net/2011027

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010960
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN WhatWeb Web Application Fingerprint Scanner Default User-Agent Detected"; flow:established,to_server; content:"|0d 0a|User-Agent|3A| WhatWeb/"; reference:url,www.morningstarsecurity.com/research/whatweb; reference:url,doc.emergingthreats.net/2010960; classtype:attempted-recon; sid:2010960; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **WhatWeb Web Application Fingerprint Scanner Default User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.morningstarsecurity.com/research/whatweb|url,doc.emergingthreats.net/2010960

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008417
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Wapiti Web Server Vulnerability Scan"; flow:to_server,established; content:"GET /"; depth:5; content:"?http|3A|//www.google."; within:100; nocase; content:"|0d 0a|User-Agent|3A 20|Python-httplib2"; distance:0; reference:url,wapiti.sourceforge.net/; reference:url,doc.emergingthreats.net/2008417; classtype:attempted-recon; sid:2008417; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Wapiti Web Server Vulnerability Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,wapiti.sourceforge.net/|url,doc.emergingthreats.net/2008417

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011808
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Inspathx Path Disclosure Scanner User-Agent Detected"; flow:established,to_server; content:"User-Agent|3A| inspath [path disclosure finder"; http_header; threshold:type limit, count 1, seconds 30, track by_src; reference:url,code.google.com/p/inspathx/; reference:url,www.darknet.org.uk/2010/09/inspathx-tool-for-finding-path-disclosure-vulnerabilities/; classtype:attempted-recon; sid:2011808; rev:4; metadata:created_at 2010_10_12, updated_at 2019_09_27;)
` 

Name : **Inspathx Path Disclosure Scanner User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/inspathx/|url,www.darknet.org.uk/2010/09/inspathx-tool-for-finding-path-disclosure-vulnerabilities/

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2019-09-27

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011809
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Inspathx Path Disclosure Scan"; flow:established,to_server; content:"GET"; http_method; content:"varhttp|3A|/"; http_uri; nocase; content:"wwwhttp|3A|/"; http_uri; nocase; content:"htmlhttp|3A|/"; http_uri; nocase; threshold:type limit, count 1, seconds 30, track by_src; reference:url,code.google.com/p/inspathx/; reference:url,www.darknet.org.uk/2010/09/inspathx-tool-for-finding-path-disclosure-vulnerabilities/; classtype:attempted-recon; sid:2011809; rev:6; metadata:created_at 2010_10_12, updated_at 2019_09_27;)
` 

Name : **Inspathx Path Disclosure Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,code.google.com/p/inspathx/|url,www.darknet.org.uk/2010/09/inspathx-tool-for-finding-path-disclosure-vulnerabilities/

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2019-09-27

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003924
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN WebHack Control Center User-Agent Inbound (WHCC/)"; flow:to_server,established; content:"User-Agent|3a| "; nocase; content:"WHCC"; fast_pattern; nocase; distance:0; within:50; pcre:"/User-Agent\:[^\n]+WHCC/i"; reference:url,www.governmentsecurity.org/forum/index.php?showtopic=5112&pid=28561&mode=threaded&start=; reference:url,doc.emergingthreats.net/2003924; classtype:trojan-activity; sid:2003924; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **WebHack Control Center User-Agent Inbound (WHCC/)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.governmentsecurity.org/forum/index.php?showtopic=5112&pid=28561&mode=threaded&start=|url,doc.emergingthreats.net/2003924

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011029
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Netsparker Default User-Agent"; flow:to_server,established; content:" Netsparker)"; http_user_agent; threshold:type limit,track by_src,count 1,seconds 60; reference:url,www.mavitunasecurity.com/communityedition/; classtype:attempted-recon; sid:2011029; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Netsparker Default User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.mavitunasecurity.com/communityedition/

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010953
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Skipfish Web Application Scan Detected"; flow:established,to_server; content:"Mozilla/5.0 SF"; http_user_agent; threshold:type limit, count 10, seconds 60, track by_src; reference:url,isc.sans.org/diary.html?storyid=8467; reference:url,code.google.com/p/skipfish/; reference:url,doc.emergingthreats.net/2010953; classtype:attempted-recon; sid:2010953; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Skipfish Web Application Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,isc.sans.org/diary.html?storyid=8467|url,code.google.com/p/skipfish/|url,doc.emergingthreats.net/2010953

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008362
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN bsqlbf Brute Force SQL Injection"; flow:established,to_server; content:"bsqlbf"; http_user_agent; nocase; reference:url,code.google.com/p/bsqlbf-v2/; reference:url,doc.emergingthreats.net/2008362; classtype:web-application-activity; sid:2008362; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **bsqlbf Brute Force SQL Injection** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-activity

URL reference : url,code.google.com/p/bsqlbf-v2/|url,doc.emergingthreats.net/2008362

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009039
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQLNinja MSSQL XPCmdShell Scan"; flow:to_server,established; content:"?param=a"; content:"exec%20master%2E%2Exp%5Fcmdshell"; distance:2; reference:url,sqlninja.sourceforge.net/index.html; classtype:attempted-recon; sid:2009039; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQLNinja MSSQL XPCmdShell Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,sqlninja.sourceforge.net/index.html

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009158
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN WebShag Web Application Scan Detected"; flow:to_server,established; content:"webshag"; http_user_agent; reference:url,www.scrt.ch/pages_en/outils.html; classtype:attempted-recon; sid:2009158; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **WebShag Web Application Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.scrt.ch/pages_en/outils.html

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011028
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN HZZP Scan in Progress calc in Headers"; flow:to_server,established; content:"GET"; http_method; content:"C|3a|/WINDOWS/system32/calc.exe"; http_header; content:"|0d 0a|"; within:9; http_header; pcre:"/^.+\x3a\s(test.)?C\:\/WINDOWS\/system32\/calc\.exe(.test)?\r$/Hm"; reference:url,www.krakowlabs.com/dev.html; reference:url,doc.emergingthreats.net/2011028; classtype:attempted-recon; sid:2011028; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **HZZP Scan in Progress calc in Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.krakowlabs.com/dev.html|url,doc.emergingthreats.net/2011028

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003869
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN ProxyReconBot CONNECT method to Mail"; flow:established,to_server; content:"CONNECT "; depth:8; content:"|3A|25 HTTP/"; within:200; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2003869; classtype:misc-attack; sid:2003869; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **ProxyReconBot CONNECT method to Mail** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,doc.emergingthreats.net/2003869

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008571
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Acunetix Version 6 Crawl/Scan Detected"; flow:to_server,established; content:"/acunetix-wvs-test-for-some-inexistent-file"; http_uri; threshold: type threshold, track by_dst, count 2, seconds 5; reference:url,www.acunetix.com/; reference:url,doc.emergingthreats.net/2008571; classtype:attempted-recon; sid:2008571; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Acunetix Version 6 Crawl/Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.acunetix.com/|url,doc.emergingthreats.net/2008571

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011030
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Netsparker Scan in Progress"; flow:to_server,established; content:"/Netsparker-"; http_uri; threshold:type limit,track by_src,count 1,seconds 60; reference:url,www.mavitunasecurity.com/communityedition/; reference:url,doc.emergingthreats.net/2011030; classtype:attempted-recon; sid:2011030; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Netsparker Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.mavitunasecurity.com/communityedition/|url,doc.emergingthreats.net/2011030

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008627
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Httprecon Web Server Fingerprint Scan"; flow:to_server,established; content:"GET"; http_method; content:"/etc/passwd?format="; http_uri; content:"><script>alert('xss')"; http_uri; content:"traversal="; http_uri; reference:url,www.computec.ch/projekte/httprecon/; reference:url,doc.emergingthreats.net/2008627; classtype:attempted-recon; sid:2008627; rev:10; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Httprecon Web Server Fingerprint Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.computec.ch/projekte/httprecon/|url,doc.emergingthreats.net/2008627

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008617
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Wikto Scan"; flow:to_server,established; content:"GET"; http_method; content:"/.adSensePostNotThereNoNobook"; http_uri; reference:url,www.sensepost.com/research/wikto/WiktoDoc1-51.htm; reference:url,doc.emergingthreats.net/2008617; classtype:attempted-recon; sid:2008617; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Wikto Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.sensepost.com/research/wikto/WiktoDoc1-51.htm|url,doc.emergingthreats.net/2008617

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008629
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Wikto Backend Data Miner Scan"; flow:to_server,established; content:"GET"; http_method; content:"/actSensePostNotThereNoNotive"; http_uri; reference:url,www.sensepost.com/research/wikto/WiktoDoc1-51.htm; reference:url,doc.emergingthreats.net/2008629; classtype:attempted-recon; sid:2008629; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Wikto Backend Data Miner Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.sensepost.com/research/wikto/WiktoDoc1-51.htm|url,doc.emergingthreats.net/2008629

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009479
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Asp-Audit Web Scan Detected"; flow:to_server,established; content:"GET"; http_method; content:"STYLE=x|3a|e/**/xpression(alert('asp-audit'))>"; http_uri; reference:url,www.hacker-soft.net/Soft/Soft_2895.htm; reference:url,wiki.remote-exploit.org/backtrack/wiki/asp-audit; reference:url,doc.emergingthreats.net/2009479; classtype:attempted-recon; sid:2009479; rev:11; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Asp-Audit Web Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.hacker-soft.net/Soft/Soft_2895.htm|url,wiki.remote-exploit.org/backtrack/wiki/asp-audit|url,doc.emergingthreats.net/2009479

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 11

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008628
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN WSFuzzer Web Application Fuzzing"; flow:to_server,established; content:"/ServiceDefinition"; http_uri; fast_pattern; content:"Python-urllib/"; depth:14; http_user_agent; reference:url,www.owasp.org/index.php/Category%3aOWASP_WSFuzzer_Project; reference:url,doc.emergingthreats.net/2008628; classtype:attempted-recon; sid:2008628; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **WSFuzzer Web Application Fuzzing** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.owasp.org/index.php/Category%3aOWASP_WSFuzzer_Project|url,doc.emergingthreats.net/2008628

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013779
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Positive Technologies XSpider Security Scanner User-Agent (PTX)"; flow:to_server,established; content:"PTX|0d 0a|"; http_header; fast_pattern; pcre:"/^User-Agent\x3a[^\n]+PTX\r$/Hm"; reference:url,www.securitylab.ru/forum/forum16/topic26800/; classtype:attempted-recon; sid:2013779; rev:5; metadata:created_at 2011_10_19, updated_at 2019_10_07;)
` 

Name : **Positive Technologies XSpider Security Scanner User-Agent (PTX)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.securitylab.ru/forum/forum16/topic26800/

CVE reference : Not defined

Creation date : 2011-10-19

Last modified date : 2019-10-07

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015484
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN w3af User-Agent 2"; flow:established,to_server; content:"w3af.sf.net"; http_header; fast_pattern; pcre:"/^User-Agent\x3a[^\r\n]+?w3af\.sf\.net/Hmi"; classtype:attempted-recon; sid:2015484; rev:3; metadata:created_at 2012_07_17, updated_at 2019_10_07;)
` 

Name : **w3af User-Agent 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-17

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015754
`alert udp $EXTERNAL_NET any -> $HOME_NET [137,138,139,445] (msg:"ET SCAN Nessus Netbios Scanning"; content:"n|00|e|00|s|00|s|00|u|00|s"; fast_pattern; reference:url,www.tenable.com/products/nessus/nessus-product-overview; classtype:attempted-recon; sid:2015754; rev:3; metadata:created_at 2012_10_01, updated_at 2019_10_07;)
` 

Name : **Nessus Netbios Scanning** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.tenable.com/products/nessus/nessus-product-overview

CVE reference : Not defined

Creation date : 2012-10-01

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015940
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SFTP/FTP Password Exposure via sftp-config.json"; flow:to_server,established; content:"/sftp-config.json"; fast_pattern; http_uri; reference:url,blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html; classtype:attempted-recon; sid:2015940; rev:3; metadata:created_at 2012_11_26, updated_at 2019_10_07;)
` 

Name : **SFTP/FTP Password Exposure via sftp-config.json** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html

CVE reference : Not defined

Creation date : 2012-11-26

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017161
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN SipCLI VOIP Scan - TCP"; flow:established,to_server; content:"|0D 0A|User-Agent|3A 20|sipcli/"; fast_pattern; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.yasinkaplan.com/SipCli/; classtype:attempted-recon; sid:2017161; rev:2; metadata:created_at 2013_07_17, updated_at 2019_10_07;)
` 

Name : **SipCLI VOIP Scan - TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.yasinkaplan.com/SipCli/

CVE reference : Not defined

Creation date : 2013-07-17

Last modified date : 2019-10-07

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017162
`alert udp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET SCAN SipCLI VOIP Scan"; content:"|0D 0A|User-Agent|3A 20|sipcli/"; fast_pattern; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.yasinkaplan.com/SipCli/; classtype:attempted-recon; sid:2017162; rev:3; metadata:created_at 2013_07_17, updated_at 2019_10_07;)
` 

Name : **SipCLI VOIP Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.yasinkaplan.com/SipCli/

CVE reference : Not defined

Creation date : 2013-07-17

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017950
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN FOCA uri"; flow:established,to_server; content:"GET"; http_method; content:"/*F0C4~1*/foca.aspx?aspxerrorpath=/"; http_uri; fast_pattern; content:!"Referer|3a 20|"; http_header; content:!"Accept|3a 20|"; http_header; content:!"Connection|3a 20|"; http_header; reference:url,blog.bannasties.com/2013/08/vulnerability-scans/; classtype:attempted-recon; sid:2017950; rev:4; metadata:created_at 2014_01_09, updated_at 2019_10_07;)
` 

Name : **FOCA uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.bannasties.com/2013/08/vulnerability-scans/

CVE reference : Not defined

Creation date : 2014-01-09

Last modified date : 2019-10-07

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018489
`alert udp $EXTERNAL_NET 10000: -> $HOME_NET 10000: (msg:"ET SCAN NMAP OS Detection Probe"; dsize:300; content:"CCCCCCCCCCCCCCCCCCCC"; fast_pattern; content:"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"; depth:255; content:"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"; within:45; classtype:attempted-recon; sid:2018489; rev:4; metadata:created_at 2014_05_20, updated_at 2019_10_07;)
` 

Name : **NMAP OS Detection Probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-05-20

Last modified date : 2019-10-07

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018754
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Possible WordPress xmlrpc.php wp.getUsersBlogs Flowbit Set"; flow:established,to_server; content:"/xmlrpc.php"; http_uri; nocase; fast_pattern; flowbits:set,ET.XMLRPC.PHP; flowbits:noalert; reference:url,isc.sans.edu/diary/+WordPress+brute+force+attack+via+wp.getUsersBlogs/18427; classtype:attempted-admin; sid:2018754; rev:4; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2014_07_23, updated_at 2019_10_07;)
` 

Name : **Possible WordPress xmlrpc.php wp.getUsersBlogs Flowbit Set** 

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

Alert Classtype : attempted-admin

URL reference : url,isc.sans.edu/diary/+WordPress+brute+force+attack+via+wp.getUsersBlogs/18427

CVE reference : Not defined

Creation date : 2014-07-23

Last modified date : 2019-10-07

Rev version : 4

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009481
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Grendel-Scan Web Application Security Scan Detected"; flow:to_server,established; content:"GET"; http_method; content:"/random"; nocase; http_uri; fast_pattern; pcre:"/\x2Frandom\w+?\x2E(?:c(?:f[cm]|gi)|ht(?:ml?|r)|(?:ws|x)dl|a(?:sp|xd)|p(?:hp3|l)|bat|swf|vbs|do)/Ui"; threshold: type threshold, track by_dst, count 20, seconds 40; reference:url,www.grendel-scan.com; reference:url,doc.emergingthreats.net/2009481; classtype:attempted-recon; sid:2009481; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **Grendel-Scan Web Application Security Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.grendel-scan.com|url,doc.emergingthreats.net/2009481

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021058
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Xenu Link Sleuth Scanner Outbound"; flow:to_server,established; content:"GET"; http_method; content:"Xenu Link Sleuth"; http_user_agent; fast_pattern; classtype:attempted-recon; sid:2021058; rev:4; metadata:created_at 2015_05_05, updated_at 2019_10_07;)
` 

Name : **Xenu Link Sleuth Scanner Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-05

Last modified date : 2019-10-07

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022243
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN COMMIX Command injection scan attempt"; flow:to_server,established; content:"|55 73 65 72 2d 41 67 65 6e 74 3a 20 63 6f 6d 6d 69 78|"; fast_pattern; http_header; threshold: type limit, count 1, seconds 60, track by_src; reference:url,github.com/stasinopoulos/commix/blob/master/README.md; classtype:web-application-activity; sid:2022243; rev:3; metadata:created_at 2015_12_11, updated_at 2019_10_07;)
` 

Name : **COMMIX Command injection scan attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,github.com/stasinopoulos/commix/blob/master/README.md

CVE reference : Not defined

Creation date : 2015-12-11

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022579
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN MySQL Malicious Scanning 1"; flow:to_server; content:"|00 03|"; offset:3; depth:2; content:"GRANT ALTER, ALTER ROUTINE"; distance:0; nocase; within:30; content:"TO root@% WITH"; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781; classtype:bad-unknown; sid:2022579; rev:2; metadata:created_at 2016_03_01, updated_at 2019_10_07;)
` 

Name : **MySQL Malicious Scanning 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781

CVE reference : Not defined

Creation date : 2016-03-01

Last modified date : 2019-10-07

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022580
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN MySQL Malicious Scanning 2"; flow:to_server; content:"|00 03|"; offset:3; depth:2; content:"set global log_bin_trust_function_creators=1"; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781; classtype:bad-unknown; sid:2022580; rev:2; metadata:created_at 2016_03_01, updated_at 2019_10_07;)
` 

Name : **MySQL Malicious Scanning 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,isc.sans.edu/diary/Quick+Analysis+of+a+Recent+MySQL+Exploit/20781

CVE reference : Not defined

Creation date : 2016-03-01

Last modified date : 2019-10-07

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023687
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Acunetix scan in progress acunetix_wvs_security_test in http_uri"; flow:established,to_server; content:"acunetix_wvs_security_test"; http_uri; fast_pattern; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.acunetix.com/; classtype:web-application-attack; sid:2023687; rev:3; metadata:affected_product Any, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2016_12_28, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Acunetix scan in progress acunetix_wvs_security_test in http_uri** 

Attack target : Web_Server

Description : Signature is matching at network scans to retrieve information about the web server. This reconnaissance to determine whether or not the target is vulnerable.

Tags : Not defined

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,www.acunetix.com/

CVE reference : Not defined

Creation date : 2016-12-28

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023688
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Acunetix scan in progress acunetix variable in http_uri"; flow:established,to_server; content:"|24|acunetix"; http_uri; fast_pattern; threshold: type limit, count 1, seconds 60, track by_src; reference:url,www.acunetix.com/; classtype:web-application-attack; sid:2023688; rev:3; metadata:affected_product Any, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2016_12_28, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Acunetix scan in progress acunetix variable in http_uri** 

Attack target : Web_Server

Description : Signature is matching at network scans to retrieve information about the web server. This reconnaissance to determine whether or not the target is vulnerable.

Tags : Not defined

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,www.acunetix.com/

CVE reference : Not defined

Creation date : 2016-12-28

Last modified date : 2019-10-07

Rev version : 3

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2013171
`alert http any any -> $HTTP_SERVERS any (msg:"ET SCAN DominoHunter Security Scan in Progress"; flow:established,to_server; content:"DominoHunter"; nocase; http_user_agent; depth:12; reference:url,packetstormsecurity.org/files/31653/DominoHunter-0.92.zip.html; classtype:web-application-attack; sid:2013171; rev:3; metadata:created_at 2011_07_02, updated_at 2019_10_11;)
` 

Name : **DominoHunter Security Scan in Progress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,packetstormsecurity.org/files/31653/DominoHunter-0.92.zip.html

CVE reference : Not defined

Creation date : 2011-07-02

Last modified date : 2019-10-11

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009159
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Toata Scanner User-Agent Detected"; flow:to_server,established; content:"Toata dragostea "; http_user_agent; depth:16; threshold: type limit, count 1, seconds 60, track by_src; reference:url,isc.sans.org/diary.html?storyid=5599; reference:url,doc.emergingthreats.net/2009159; classtype:attempted-recon; sid:2009159; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Toata Scanner User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,isc.sans.org/diary.html?storyid=5599|url,doc.emergingthreats.net/2009159

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009154
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Automated Injection Tool User-Agent (AutoGetColumn)"; flow:established,to_server; content:"AutoGetColumn"; http_user_agent; depth:13; reference:url,doc.emergingthreats.net/2009154; classtype:attempted-recon; sid:2009154; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Automated Injection Tool User-Agent (AutoGetColumn)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009154

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009480
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Grendel Web Scan - Default User Agent Detected"; flow:to_server,established; content:"Mozilla/5.0 (compatible|3b 20|Grendel-Scan"; nocase; http_user_agent; depth:37; fast_pattern; content:"http|3a|//www.grendel-scan.com"; http_header; nocase; threshold: type limit, track by_dst, count 1, seconds 60; reference:url,www.grendel-scan.com; reference:url,doc.emergingthreats.net/2009480; classtype:attempted-recon; sid:2009480; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Grendel Web Scan - Default User Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.grendel-scan.com|url,doc.emergingthreats.net/2009480

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016032
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN JCE Joomla Scanner"; flow:established,to_server; content:"BOT/0.1 (BOT for JCE)"; http_user_agent; depth:21; classtype:web-application-attack; sid:2016032; rev:4; metadata:created_at 2012_12_13, updated_at 2019_10_11;)
` 

Name : **JCE Joomla Scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-13

Last modified date : 2019-10-11

Rev version : 4

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010019
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomcat Web Application Manager scanning"; flow:established,to_server; content:"GET"; http_method; content:"/manager/html"; nocase; fast_pattern; http_uri; content:"Mozilla/3.0 (compatible|3b 20|Indy Library)"; http_user_agent; depth:38; isdataat:!1,relative; content:"Authorization|3a 20|Basic"; http_header; content:!"Proxy-Authorization|3a 20|Basic"; nocase; http_header; reference:url,doc.emergingthreats.net/2010019; classtype:attempted-recon; sid:2010019; rev:10; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Tomcat Web Application Manager scanning** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010019

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003634
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Suspicious User-Agent - get-minimal - Possible Vuln Scan"; flow:established,to_server; content:"get-minimal"; http_user_agent; depth:11; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2003634; classtype:attempted-admin; sid:2003634; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent - get-minimal - Possible Vuln Scan** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2003634

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007757
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN w3af User Agent"; flow: established,to_server; content:"w3af.sourceforge.net"; http_user_agent; depth:20; reference:url,w3af.sourceforge.net; reference:url,doc.emergingthreats.net/2007757; classtype:attempted-recon; sid:2007757; rev:12; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **w3af User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,w3af.sourceforge.net|url,doc.emergingthreats.net/2007757

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 12

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011089
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN DavTest WebDav Vulnerability Scanner Default User Agent Detected"; flow:established,to_server; content:"DAV.pm/v"; depth:8; http_user_agent; reference:url,www.darknet.org.uk/2010/04/davtest-webdav-vulerability-scanning-scanner-tool/; reference:url,code.google.com/p/davtest/; reference:url,doc.emergingthreats.net/2011089; classtype:attempted-recon; sid:2011089; rev:5; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **DavTest WebDav Vulnerability Scanner Default User Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.darknet.org.uk/2010/04/davtest-webdav-vulerability-scanning-scanner-tool/|url,code.google.com/p/davtest/|url,doc.emergingthreats.net/2011089

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009483
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Grabber.py Web Scan Detected"; flow:to_server,established; content:"Grabber"; depth:7; http_user_agent; reference:url,rgaucher.info/beta/grabber/; reference:url,doc.emergingthreats.net/2009483; classtype:attempted-recon; sid:2009483; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Grabber.py Web Scan Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,rgaucher.info/beta/grabber/|url,doc.emergingthreats.net/2009483

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008729
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Mini MySqlatOr SQL Injection Scanner"; flow:to_server,established; content:"prog.CustomCrawler"; depth:18; http_user_agent; reference:url,www.scrt.ch/pages_en/minimysqlator.html; reference:url,doc.emergingthreats.net/2008729; classtype:attempted-recon; sid:2008729; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Mini MySqlatOr SQL Injection Scanner** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,www.scrt.ch/pages_en/minimysqlator.html|url,doc.emergingthreats.net/2008729

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009769
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN SQL Power Injector SQL Injection User Agent Detected"; flow:to_server,established; content:"SQL Power Injector"; depth:18; http_user_agent; reference:url,www.sqlpowerinjector.com/index.htm; reference:url,en.wikipedia.org/wiki/Sql_injection; reference:url,doc.emergingthreats.net/2009769; classtype:attempted-recon; sid:2009769; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **SQL Power Injector SQL Injection User Agent Detected** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,www.sqlpowerinjector.com/index.htm|url,en.wikipedia.org/wiki/Sql_injection|url,doc.emergingthreats.net/2009769

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 5

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010768
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Open-Proxy ScannerBot (webcollage-UA) "; flow:established,to_server; content:"webcollage/"; depth:11; nocase; http_user_agent; reference:url, stateofsecurity.com/?p=526; reference:url,www.botsvsbrowsers.com/details/214715/index.html; reference:url,doc.emergingthreats.net/2010768; classtype:bad-unknown; sid:2010768; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Open-Proxy ScannerBot (webcollage-UA) ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url, stateofsecurity.com/?p=526|url,www.botsvsbrowsers.com/details/214715/index.html|url,doc.emergingthreats.net/2010768

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008537
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Hmap Webserver Fingerprint Scan"; flow:to_server,established; urilen:1; content:"GET"; http_method; content:"4.75 [en] (Windows NT 5.0"; http_user_agent; http_protocol; content:"HTTP/1.0"; reference:url,www.ujeni.murkyroc.com/hmap/; reference:url,doc.emergingthreats.net/2008537; classtype:attempted-recon; sid:2008537; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Hmap Webserver Fingerprint Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.ujeni.murkyroc.com/hmap/|url,doc.emergingthreats.net/2008537

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011497
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Hydra User-Agent"; flow:established,to_server; content:"Mozilla/4.0 (Hydra)"; nocase; http_user_agent; fast_pattern; depth:19; threshold: type limit, track by_src,count 1, seconds 60; reference:url,freeworld.thc.org/thc-hydra; classtype:attempted-recon; sid:2011497; rev:5; metadata:created_at 2010_09_27, updated_at 2020_04_20;)
` 

Name : **Hydra User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,freeworld.thc.org/thc-hydra

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2020-04-20

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018782
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Internet Scanning Project HTTP scan"; flow:established,to_server; content:"research-scanner/"; http_user_agent; depth:17; content:"internetscanningproject.org"; distance:0; http_header; reference:url,www.internetscanningproject.org; classtype:attempted-recon; sid:2018782; rev:3; metadata:created_at 2014_07_25, updated_at 2019_10_15;)
` 

Name : **Internet Scanning Project HTTP scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.internetscanningproject.org

CVE reference : Not defined

Creation date : 2014-07-25

Last modified date : 2019-10-15

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009833
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN WITOOL SQL Injection Scan"; flow:to_server,established; content:"union+select"; http_raw_uri; content:"select+user"; http_raw_uri; content:"Mozilla/4.0 (compatible|3b 20|MSIE 6.0|3b 20|Windows NT 5.0|3b 20|MyIE2"; fast_pattern; http_user_agent; depth:56; threshold: type threshold, track by_dst, count 2, seconds 30; reference:url,witool.sourceforge.net/; reference:url,doc.emergingthreats.net/2009833; classtype:attempted-recon; sid:2009833; rev:12; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_15;)
` 

Name : **WITOOL SQL Injection Scan** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-recon

URL reference : url,witool.sourceforge.net/|url,doc.emergingthreats.net/2009833

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-15

Rev version : 12

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013492
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN McAfee/Foundstone Scanner Web Scan"; flow:established,to_server; content:"Mozilla/5.0 (Windows|3b 20|Windows NT 6.1|3b 20|en-US)"; http_user_agent; fast_pattern; depth:44; isdataat:!1,relative; content:"|0D 0A|Accept-Encoding|3a 20|text|0D 0A|"; http_header; threshold: type both, count 2, seconds 120, track by_src; reference:url,www.mcafee.com/us/products/vulnerability-manager.aspx; classtype:attempted-recon; sid:2013492; rev:5; metadata:created_at 2011_08_30, updated_at 2020_04_20;)
` 

Name : **McAfee/Foundstone Scanner Web Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.mcafee.com/us/products/vulnerability-manager.aspx

CVE reference : Not defined

Creation date : 2011-08-30

Last modified date : 2020-04-20

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029015
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|DEMONS"; http_header; fast_pattern; pcre:"/^DEMONS(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029015; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029016
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Hakai"; http_header; fast_pattern; pcre:"/^Hakai(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029016; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029017
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Messiah"; http_header; fast_pattern; pcre:"/^Messiah(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029017; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029018
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Liquor"; http_header; fast_pattern; pcre:"/^Liquor(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029018; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029019
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|B4ckdoor|0d 0a|"; http_header; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029019; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029020
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Nija"; http_header; fast_pattern; pcre:"/^Nija(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029020; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029021
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Gemini"; http_header; fast_pattern; pcre:"/^Gemini(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029021; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029023
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Kayla"; http_header; fast_pattern; pcre:"/^Kayla(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029023; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029024
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Sector"; http_header; fast_pattern; pcre:"/^Sector(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029024; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029026
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|OSIRIS"; http_header; fast_pattern; pcre:"/^OSIRIS(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029026; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2019_11_21;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2019-11-21

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029054
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Zmap User-Agent (zgrab)"; flow:established,to_server; content:"Mozilla/5.0 zgrab/0.x"; http_user_agent; depth:21; isdataat:!1,relative; classtype:network-scan; sid:2029054; rev:1; metadata:created_at 2019_11_26, updated_at 2019_11_26;)
` 

Name : **Zmap User-Agent (zgrab)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-26

Last modified date : 2019-11-26

Rev version : 2

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008311
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Watchfire AppScan Web App Vulnerability Scanner"; flow:established,to_server; content:"/appscan_fingerprint/mac_address"; nocase; http_uri; reference:url,www.watchfire.com/products/appscan/default.aspx; reference:url,doc.emergingthreats.net/2008311; classtype:attempted-recon; sid:2008311; rev:8; metadata:created_at 2010_07_30, updated_at 2019_12_19;)
` 

Name : **Watchfire AppScan Web App Vulnerability Scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.watchfire.com/products/appscan/default.aspx|url,doc.emergingthreats.net/2008311

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-12-19

Rev version : 8

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029208
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Dark Nexus IoT Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|dark_NeXus"; http_header; fast_pattern; classtype:attempted-admin; sid:2029208; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_12_30, updated_at 2019_12_30;)
` 

Name : **Dark Nexus IoT Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-12-30

Last modified date : 2019-12-30

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029317
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomato Router Default Credentials (admin:admin)"; flow:to_server,established; content:"GET"; http_method; content:"/admin-scripts.asp"; http_uri; nocase; content:"Authorization|3a 20|Basic|20|YWRtaW46YWRtaW4="; http_header; metadata: former_category SCAN; reference:url,unit42.paloaltonetworks.com/muhstik-botnet-attacks-tomato-routers-to-harvest-new-iot-devices/; classtype:attempted-admin; sid:2029317; rev:1; metadata:attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2020_01_23, performance_impact Low, updated_at 2020_01_23;)
` 

Name : **Tomato Router Default Credentials (admin:admin)** 

Attack target : Networking_Equipment

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,unit42.paloaltonetworks.com/muhstik-botnet-attacks-tomato-routers-to-harvest-new-iot-devices/

CVE reference : Not defined

Creation date : 2020-01-23

Last modified date : 2020-01-23

Rev version : 2

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2029318
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomato Router Default Credentials (root:admin)"; flow:to_server,established; content:"GET"; http_method; content:"/admin-scripts.asp"; http_uri; nocase; content:"Authorization|3a 20|Basic|20|cm9vdDphZG1pbg=="; http_header; metadata: former_category SCAN; reference:url,unit42.paloaltonetworks.com/muhstik-botnet-attacks-tomato-routers-to-harvest-new-iot-devices/; classtype:attempted-admin; sid:2029318; rev:1; metadata:attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2020_01_23, performance_impact Low, updated_at 2020_01_23;)
` 

Name : **Tomato Router Default Credentials (root:admin)** 

Attack target : Networking_Equipment

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,unit42.paloaltonetworks.com/muhstik-botnet-attacks-tomato-routers-to-harvest-new-iot-devices/

CVE reference : Not defined

Creation date : 2020-01-23

Last modified date : 2020-01-23

Rev version : 2

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2013791
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Apache mod_proxy Reverse Proxy Exposure 1"; flow:established,to_server; http_request_line; content:"GET @"; depth:5; reference:url,www.contextis.com/research/blog/reverseproxybypass/; reference:url,mail-archives.apache.org/mod_mbox/httpd-announce/201110.mbox/%3C20111005141541.GA7696@redhat.com%3E; classtype:attempted-recon; sid:2013791; rev:3; metadata:created_at 2011_10_24, updated_at 2020_02_05;)
` 

Name : **Apache mod_proxy Reverse Proxy Exposure 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.contextis.com/research/blog/reverseproxybypass/|url,mail-archives.apache.org/mod_mbox/httpd-announce/201110.mbox/%3C20111005141541.GA7696@redhat.com%3E

CVE reference : Not defined

Creation date : 2011-10-24

Last modified date : 2020-02-05

Rev version : 3

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009220
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomcat upload from external source"; flow:to_server,established; flowbits:isset,ET.Tomcat.login.attempt; content:"POST"; http_method; content:"/manager/html/upload"; http_uri; nocase; reference:url,tomcat.apache.org; reference:url,doc.emergingthreats.net/2009220; classtype:successful-admin; sid:2009220; rev:7; metadata:created_at 2010_07_30, updated_at 2020_02_10;)
` 

Name : **Tomcat upload from external source** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,tomcat.apache.org|url,doc.emergingthreats.net/2009220

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-10

Rev version : 7

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029022
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Hello, World"; http_header; nocase; fast_pattern; pcre:"/^Hello, World(?:(?:\/|\s)[0-9]\.0)?$/Vi"; metadata: former_category SCAN; classtype:attempted-admin; sid:2029022; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2020_02_13;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2020-02-13

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029473
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai User-Agent Observed (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Ankit|0d 0a|"; http_header; nocase; fast_pattern; metadata: former_category SCAN; classtype:attempted-admin; sid:2029473; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_02_17, updated_at 2020_02_17;)
` 

Name : **ELF/Mirai User-Agent Observed (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-02-17

Last modified date : 2020-02-17

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009217
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Tomcat admin-admin login credentials"; flow:to_server,established; content:"/manager/html"; nocase; http_uri; content:"|0d 0a|Authorization|3a 20|Basic|20|YWRtaW46YWRtaW4=|0d 0a|"; fast_pattern; http_header; flowbits:set,ET.Tomcat.login.attempt; reference:url,tomcat.apache.org; reference:url,doc.emergingthreats.net/2009217; classtype:attempted-admin; sid:2009217; rev:9; metadata:created_at 2010_07_30, updated_at 2020_02_24;)
` 

Name : **Tomcat admin-admin login credentials** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,tomcat.apache.org|url,doc.emergingthreats.net/2009217

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-24

Rev version : 9

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021949
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN abdullkarem Wordpress PHP Scanner"; flow:established,to_server; content:"GET"; http_method; content:".php?"; nocase; http_uri; content:"&php"; nocase; http_uri; distance:0; content:"&wphp"; nocase; http_uri; distance:0; content:"&abdullkarem="; nocase; http_uri; fast_pattern; distance:0; http_protocol; content:"HTTP/1.0"; depth:8; isdataat:!1,relative; http_header_names; content:"|0d 0a|Host|0d 0a|"; depth:8; classtype:web-application-attack; sid:2021949; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2015_10_14, updated_at 2020_02_28;)
` 

Name : **abdullkarem Wordpress PHP Scanner** 

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

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-10-14

Last modified date : 2020-02-28

Rev version : 3

Category : SCAN

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029577
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Polaris Botnet User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|polaris botnet"; http_header; fast_pattern; classtype:attempted-admin; sid:2029577; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_05, updated_at 2020_03_05;)
` 

Name : **Polaris Botnet User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-05

Last modified date : 2020-03-05

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013792
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN Apache mod_proxy Reverse Proxy Exposure 2"; flow:established,to_server; content:"|3a|@"; http_uri; http_request_line; content:"GET|20 3a|@"; depth:6; reference:url,www.contextis.com/research/blog/reverseproxybypass/; reference:url,mail-archives.apache.org/mod_mbox/httpd-announce/201110.mbox/%3C20111005141541.GA7696@redhat.com%3E; classtype:attempted-recon; sid:2013792; rev:5; metadata:created_at 2011_10_24, updated_at 2020_03_11;)
` 

Name : **Apache mod_proxy Reverse Proxy Exposure 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.contextis.com/research/blog/reverseproxybypass/|url,mail-archives.apache.org/mod_mbox/httpd-announce/201110.mbox/%3C20111005141541.GA7696@redhat.com%3E

CVE reference : Not defined

Creation date : 2011-10-24

Last modified date : 2020-03-11

Rev version : 5

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013416
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET SCAN libwww-perl GET to // with specific HTTP header ordering without libwww-perl User-Agent"; flow:established,to_server; content:"TE|3a 20|deflate,gzip|3b|q=0.3|0d 0a|Connection|3a 20|TE, close|0d 0a|Host|3a 20|"; http_header; depth:53; content:"User-Agent|3a 20|"; within:100; http_header; content:!"libwww-perl/"; http_user_agent; http_header_names; content:"|0d 0a|TE|0d 0a|Host|0d 0a|User-Agent|0d 0a 0d 0a|"; depth:26; isdataat:!1,relative; http_request_line; content:"GET //"; fast_pattern; depth:6; threshold:type threshold, track by_dst, count 10, seconds 20; classtype:attempted-recon; sid:2013416; rev:10; metadata:created_at 2011_08_16, updated_at 2020_03_11;)
` 

Name : **libwww-perl GET to // with specific HTTP header ordering without libwww-perl User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-16

Last modified date : 2020-03-11

Rev version : 10

Category : SCAN

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029645
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Polaris Botnet User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|polaris|0d 0a|"; fast_pattern; http_header; metadata: former_category SCAN; classtype:attempted-admin; sid:2029645; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_18, updated_at 2020_03_18;)
` 

Name : **Polaris Botnet User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-18

Last modified date : 2020-03-18

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029025
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|APEP"; http_header; fast_pattern; metadata: former_category MALWARE; classtype:attempted-admin; sid:2029025; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_21, updated_at 2020_03_23;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-21

Last modified date : 2020-03-23

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029759
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|DVRBOT"; http_header; fast_pattern; metadata: former_category SCAN; classtype:attempted-admin; sid:2029759; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_29, updated_at 2020_03_29;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-29

Last modified date : 2020-03-29

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029763
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|iamdelta"; http_header; fast_pattern; classtype:attempted-admin; sid:2029763; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_30, updated_at 2020_03_30;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-30

Last modified date : 2020-03-30

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029769
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|NoIr_x.86/"; http_header; fast_pattern; classtype:attempted-admin; sid:2029769; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_31, updated_at 2020_03_31;)
` 

Name : **Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-31

Last modified date : 2020-03-31

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029792
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Hello/"; http_header; fast_pattern; classtype:attempted-admin; sid:2029792; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_04_02, updated_at 2020_04_02;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-02

Last modified date : 2020-04-02

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029790
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|XTC|0d 0a|"; http_header; fast_pattern; classtype:attempted-admin; sid:2029790; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_04_02, updated_at 2020_04_03;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-02

Last modified date : 2020-04-03

Rev version : 3

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029808
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|XTC BOTNET|0d 0a|"; fast_pattern; http_header; classtype:attempted-admin; sid:2029808; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_04_03, updated_at 2020_04_03;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-03

Last modified date : 2020-04-03

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029929
`alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN ELF/Mirai Variant User-Agent (Inbound)"; flow:established,to_server; content:"User-Agent|3a 20|Kratos"; fast_pattern; http_header; classtype:attempted-admin; sid:2029929; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **ELF/Mirai Variant User-Agent (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : SCAN

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

