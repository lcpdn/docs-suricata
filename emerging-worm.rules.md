# 2003292
`#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM Allaple ICMP Sweep Ping Outbound"; icode:0; itype:8; content:"Babcdefghijklmnopqrstuvwabcdefghi"; threshold: type both, count 1, seconds 60, track by_src; reference:url,www.sophos.com/virusinfo/analyses/w32allapleb.html; reference:url,isc.sans.org/diary.html?storyid=2451; reference:url,doc.emergingthreats.net/2003292; classtype:trojan-activity; sid:2003292; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Allaple ICMP Sweep Ping Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sophos.com/virusinfo/analyses/w32allapleb.html|url,isc.sans.org/diary.html?storyid=2451|url,doc.emergingthreats.net/2003292

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003294
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WORM Allaple ICMP Sweep Ping Inbound"; icode:0; itype:8; content:"Babcdefghijklmnopqrstuvwabcdefghi"; threshold: type both, count 1, seconds 60, track by_src; reference:url,www.sophos.com/virusinfo/analyses/w32allapleb.html; reference:url,isc.sans.org/diary.html?storyid=2451; reference:url,doc.emergingthreats.net/2003294; classtype:trojan-activity; sid:2003294; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Allaple ICMP Sweep Ping Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sophos.com/virusinfo/analyses/w32allapleb.html|url,isc.sans.org/diary.html?storyid=2451|url,doc.emergingthreats.net/2003294

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003293
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WORM Allaple ICMP Sweep Reply Inbound"; icode:0; itype:0; content:"Babcdefghijklmnopqrstuvwabcdefghi"; threshold: type both, count 1, seconds 60, track by_dst; reference:url,www.sophos.com/virusinfo/analyses/w32allapleb.html; reference:url,isc.sans.org/diary.html?storyid=2451; reference:url,doc.emergingthreats.net/2003293; classtype:trojan-activity; sid:2003293; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Allaple ICMP Sweep Reply Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sophos.com/virusinfo/analyses/w32allapleb.html|url,isc.sans.org/diary.html?storyid=2451|url,doc.emergingthreats.net/2003293

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002683
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WORM shell bot perl code download"; flow:to_client,established; content:"# ShellBOT"; nocase; reference:url,doc.emergingthreats.net/2002683; classtype:trojan-activity; sid:2002683; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **shell bot perl code download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2002683

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002684
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WORM Shell Bot Code Download"; flow:to_client,established; content:"##################### IRC #######################"; nocase; reference:url,doc.emergingthreats.net/2002684; classtype:trojan-activity; sid:2002684; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Shell Bot Code Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2002684

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007914
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET WORM SDBot HTTP Checkin"; flow:established,to_server; content:"|0d 0a|User-Agent|3a| Mozilla/3.0 (compatible|3b| Indy Library)|0d 0a 0d 0a|quem=dodoi&tit="; content:"&txt="; distance:0; within:40; reference:url,doc.emergingthreats.net/2007914; classtype:trojan-activity; sid:2007914; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SDBot HTTP Checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007914

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003295
`#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM Allaple ICMP Sweep Reply Outbound"; icode:0; itype:0; content:"Babcdefghijklmnopqrstuvwabcdefghi"; threshold: type both, count 1, seconds 60, track by_dst; reference:url,www.sophos.com/virusinfo/analyses/w32allapleb.html; reference:url,isc.sans.org/diary.html?storyid=2451; reference:url,doc.emergingthreats.net/2003295; classtype:trojan-activity; sid:2003295; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Allaple ICMP Sweep Reply Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sophos.com/virusinfo/analyses/w32allapleb.html|url,isc.sans.org/diary.html?storyid=2451|url,doc.emergingthreats.net/2003295

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102004
`alert udp $HOME_NET any -> $EXTERNAL_NET 1434 (msg:"GPL WORM Slammer Worm propagation attempt OUTBOUND"; content:"|04|"; depth:1; content:"|81 F1 03 01 04 9B 81 F1|"; content:"sock"; content:"send"; reference:bugtraq,5310; reference:bugtraq,5311; reference:cve,2002-0649; reference:nessus,11214; reference:url,vil.nai.com/vil/content/v_99992.htm; classtype:misc-attack; sid:2102004; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Slammer Worm propagation attempt OUTBOUND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,5310|bugtraq,5311|cve,2002-0649|nessus,11214|url,vil.nai.com/vil/content/v_99992.htm

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WORM

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014401
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM W32/Rimecud /qvod/ff.txt Checkin"; flow:established,to_server; content:"/qvod/ff.txt"; http_uri; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FRimecud; reference:md5,f97e1c4aefbd2595fcfeb0f482c47517; reference:md5,f96a29bcf6cba870efd8f7dd9344c39e; reference:md5,fae8675502d909d6b546c111625bcfba; classtype:trojan-activity; sid:2014401; rev:2; metadata:created_at 2012_03_19, updated_at 2012_03_19;)
` 

Name : **W32/Rimecud /qvod/ff.txt Checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FRimecud|md5,f97e1c4aefbd2595fcfeb0f482c47517|md5,f96a29bcf6cba870efd8f7dd9344c39e|md5,fae8675502d909d6b546c111625bcfba

CVE reference : Not defined

Creation date : 2012-03-19

Last modified date : 2012-03-19

Rev version : 2

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014402
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM W32/Rimecud wg.txt Checkin"; flow:established,to_server; content:"/wg.txt"; http_uri; reference:md5,a89f7289d5cce821a194542e90026082; reference:md5,fd56ce176889d4fbe588760a1da6462b; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FRimecud; classtype:trojan-activity; sid:2014402; rev:2; metadata:created_at 2012_03_19, updated_at 2012_03_19;)
` 

Name : **W32/Rimecud wg.txt Checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,a89f7289d5cce821a194542e90026082|md5,fd56ce176889d4fbe588760a1da6462b|url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FRimecud

CVE reference : Not defined

Creation date : 2012-03-19

Last modified date : 2012-03-19

Rev version : 2

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103272
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3127:3198 (msg:"GPL WORM mydoom.a backdoor upload/execute attempt"; flow:to_server,established; content:"|85 13|<|9E A2|"; depth:5; classtype:trojan-activity; sid:2103272; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mydoom.a backdoor upload/execute attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : WORM

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017404
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM W32/Njw0rm CnC Beacon"; flow:established,to_server; content:"lv0njxq80"; depth:9; content:"njxq80"; distance:0; metadata: former_category WORM; reference:url,www.fireeye.com/blog/technical/malware-research/2013/08/njw0rm-brother-from-the-same-mother.html; reference:md5,4c60493b14c666c56db163203e819272; reference:md5,b0e1d20accd9a2ed29cdacb803e4a89d; classtype:trojan-activity; sid:2017404; rev:3; metadata:created_at 2013_08_30, updated_at 2013_08_30;)
` 

Name : **W32/Njw0rm CnC Beacon** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : url,www.fireeye.com/blog/technical/malware-research/2013/08/njw0rm-brother-from-the-same-mother.html|md5,4c60493b14c666c56db163203e819272|md5,b0e1d20accd9a2ed29cdacb803e4a89d

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2013-08-30

Rev version : 3

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001689
`#alert tcp $HOME_NET any -> !$SQL_SERVERS 3306 (msg:"ET WORM Potential MySQL bot scanning for SQL server"; flow:to_server; flags:S,12; reference:url,isc.sans.org/diary.php?date=2005-01-27; reference:url,doc.emergingthreats.net/2001689; classtype:trojan-activity; sid:2001689; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Potential MySQL bot scanning for SQL server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,isc.sans.org/diary.php?date=2005-01-27|url,doc.emergingthreats.net/2001689

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018132
`alert http any any -> $HOME_NET 8080 (msg:"ET WORM TheMoon.linksys.router 2"; flow:to_server,established; content:"POST"; http_method; content:"/tmUnblock.cgi"; http_uri; reference:url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630; reference:url,devttys0.com/2014/02/wrt120n-fprintf-stack-overflow/; classtype:trojan-activity; sid:2018132; rev:4; metadata:created_at 2014_02_13, updated_at 2014_02_13;)
` 

Name : **TheMoon.linksys.router 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630|url,devttys0.com/2014/02/wrt120n-fprintf-stack-overflow/

CVE reference : Not defined

Creation date : 2014-02-13

Last modified date : 2014-02-13

Rev version : 4

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018155
`alert http any any -> $HOME_NET 8080 (msg:"ET WORM TheMoon.linksys.router 3"; flow:to_server,established; content:"POST"; http_method; content:"/hndUnblock.cgi"; http_uri; reference:url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630; reference:url,exploit-db.com/exploits/31683/; reference:url,devttys0.com/2014/02/wrt120n-fprintf-stack-overflow/; classtype:trojan-activity; sid:2018155; rev:4; metadata:created_at 2014_02_18, updated_at 2014_02_18;)
` 

Name : **TheMoon.linksys.router 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630|url,exploit-db.com/exploits/31683/|url,devttys0.com/2014/02/wrt120n-fprintf-stack-overflow/

CVE reference : Not defined

Creation date : 2014-02-18

Last modified date : 2014-02-18

Rev version : 4

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012201
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM Possible Worm Sohanad.Z or Other Infection Request for setting.nql"; flow:established,to_server; content:"/setting.nql"; nocase; http_uri; reference:url,www.threatexpert.com/report.aspx?md5=a70aad8f27957702febfa162556dc5b5; classtype:trojan-activity; sid:2012201; rev:4; metadata:created_at 2011_01_17, updated_at 2011_01_17;)
` 

Name : **Possible Worm Sohanad.Z or Other Infection Request for setting.nql** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.threatexpert.com/report.aspx?md5=a70aad8f27957702febfa162556dc5b5

CVE reference : Not defined

Creation date : 2011-01-17

Last modified date : 2011-01-17

Rev version : 4

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018131
`alert http any any -> $HOME_NET 8080 (msg:"ET WORM TheMoon.linksys.router 1"; flow:established; urilen:7; content:"GET"; http_method; content:"/HNAP1/"; http_uri; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/W"; reference:url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630; classtype:trojan-activity; sid:2018131; rev:5; metadata:created_at 2014_02_13, updated_at 2014_02_13;)
` 

Name : **TheMoon.linksys.router 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,isc.sans.edu/forums/diary/Linksys+Worm+Captured/17630

CVE reference : Not defined

Creation date : 2014-02-13

Last modified date : 2014-02-13

Rev version : 5

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008020
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM Win32.Socks.s HTTP Post Checkin"; flow:established,to_server; content:"POST"; http_method; content:".php"; http_uri; content:"proc=[System Process]|0a|"; http_client_body; depth:22; reference:url,doc.emergingthreats.net/2008020; classtype:trojan-activity; sid:2008020; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Win32.Socks.s HTTP Post Checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008020

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012739
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM Rimecud Worm checkin"; flow:established,to_server; content:"GET"; http_method; content:"Mozilla/3.0 (compatible|3b 20|Indy Library)"; http_user_agent; depth:38; content:"/taskx.txt"; http_uri; fast_pattern; reference:url,www.threatexpert.com/report.aspx?md5=9623efa133415d19c941ef92a4f921fc; classtype:trojan-activity; sid:2012739; rev:3; metadata:created_at 2011_04_29, updated_at 2019_10_11;)
` 

Name : **Rimecud Worm checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.threatexpert.com/report.aspx?md5=9623efa133415d19c941ef92a4f921fc

CVE reference : Not defined

Creation date : 2011-04-29

Last modified date : 2019-10-11

Rev version : 3

Category : WORM

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

