# 2003284
`#alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 IPv6 Inbound Connect Request (Windows Source)"; dsize:10<>23; flow:established,to_server; content:"|05 01 00 04|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003284; classtype:protocol-command-decode; sid:2003284; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 IPv6 Inbound Connect Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003284

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003285
`#alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 IPv6 Inbound Connect Request (Linux Source)"; dsize:10<>23; flow:established,to_server; content:"|05 01 00 04|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003285; classtype:protocol-command-decode; sid:2003285; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 IPv6 Inbound Connect Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003285

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003288
`#alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Bind Inbound (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 02|"; depth:2; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003288; classtype:protocol-command-decode; sid:2003288; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Bind Inbound (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003288

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003289
`#alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Bind Inbound (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 02|"; depth:2; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003289; classtype:protocol-command-decode; sid:2003289; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Bind Inbound (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003289

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003290
`#alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Bind Inbound (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 02 00 01|"; depth:4; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003290; classtype:protocol-command-decode; sid:2003290; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Bind Inbound (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003290

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003291
`#alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Bind Inbound (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 02 00 01|"; depth:4; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003291; classtype:protocol-command-decode; sid:2003291; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Bind Inbound (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003291

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009295
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET INFO Suspicious Mozilla User-Agent Likely Fake (Mozilla/5.0)"; flow:to_server,established; content:"|0d 0a|User-Agent|3a| Mozilla/5.0|0d 0a|"; nocase; content:!"|0d 0a|Host|3a| download.releasenotes.nokia.com"; content:!"Mozilla/5.0|0d 0a|Connection|3a| Close|0d 0a 0d 0a|"; metadata: former_category INFO; reference:url,doc.emergingthreats.net/2009295; classtype:trojan-activity; sid:2009295; rev:9; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **Suspicious Mozilla User-Agent Likely Fake (Mozilla/5.0)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009295

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 9

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003513
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Mozilla User-Agent typo (MOzilla/4.0)"; flow:to_server,established; content:"User-Agent|3a| M|4f|zilla/"; http_header; metadata: former_category INFO; reference:url,doc.emergingthreats.net/2003513; classtype:trojan-activity; sid:2003513; rev:11; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **Suspicious Mozilla User-Agent typo (MOzilla/4.0)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2003513

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 11

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014475
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - Java Class Download By Vulnerable Client"; flow:from_server,established; flowbits:isset,ET.http.javaclient.vulnerable; content:"|0D 0A 0D 0A CA FE BA BE|"; classtype:trojan-activity; sid:2014475; rev:6; metadata:created_at 2012_04_04, updated_at 2012_04_04;)
` 

Name : **JAVA - Java Class Download By Vulnerable Client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-04

Last modified date : 2012-04-04

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014474
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - Java Class Download"; flow:from_server,established; flowbits:isnotset,ET.http.javaclient.vulnerable; flowbits:isset,ET.http.javaclient; content:"|0D 0A 0D 0A CA FE BA BE|"; classtype:trojan-activity; sid:2014474; rev:6; metadata:created_at 2012_04_04, updated_at 2012_04_04;)
` 

Name : **JAVA - Java Class Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-04

Last modified date : 2012-04-04

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014514
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - OSX Executable Download - Multi Arch w/Intel"; flow:established,to_client;  content:"|0d 0a 0d 0a CA FE BA BE|"; content:"|CE FA ED FE|"; distance:0; content:"__TEXT"; distance:0; classtype:misc-activity; sid:2014514; rev:7; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - OSX Executable Download - Multi Arch w/Intel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014516
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - OSX Executable Download - Intel Arch"; flow:established,to_client; content:"|0D 0A 0D 0A CE FA ED FE|"; content:"__TEXT"; distance:0; classtype:misc-activity; sid:2014516; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - OSX Executable Download - Intel Arch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014517
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - OSX Executable Download - PowerPC Arch"; flow:established,to_client; content:"|0D 0A 0D 0A FE ED FA CE|"; content:"__TEXT"; distance:0; classtype:misc-activity; sid:2014517; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - OSX Executable Download - PowerPC Arch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014515
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - OSX Executable Download - Multi Arch w/PowerPC"; flow:established,to_client; content:"|0D 0A 0D 0A CA FE BA BE|"; content:"|FE ED FA CE|"; distance:0; content:"__TEXT"; distance:0; classtype:misc-activity; sid:2014515; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - OSX Executable Download - Multi Arch w/PowerPC** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014518
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - OSX Disk Image Download"; flow:established,to_client; content:"|0D 0A 0D 0A|"; content:"<plist version="; distance:0; content:"Apple_partition_map"; distance:0; content:"Apple_HFS"; distance:0; classtype:misc-activity; sid:2014518; rev:5; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - OSX Disk Image Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014567
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE Download With Content Type Specified As Empty"; flow:established,to_client; content:"Content-Type|3A 20 0D 0A|"; content:"|0d 0a 0d 0a|"; distance:0; content:"MZ"; within:2; isdataat:80,relative; content:"This program "; distance:0; content:"PE|00|"; distance:0; reference:md5,d51218653323e48672023806f6ace26b; classtype:trojan-activity; sid:2014567; rev:5; metadata:created_at 2012_04_16, updated_at 2012_04_16;)
` 

Name : **EXE Download With Content Type Specified As Empty** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,d51218653323e48672023806f6ace26b

CVE reference : Not defined

Creation date : 2012-04-16

Last modified date : 2012-04-16

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014575
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Potential Malicious PDF (EmbeddedFiles) improper case"; flow:from_server,established; content:"|0d 0a 0d 0a|%PDF"; content:"/EmbeddedFiles"; within:128; nocase; content:!"/EmbeddedFiles"; distance:-14; within:14; reference:url,blog.didierstevens.com/2009/07/01/embedding-and-hiding-files-in-pdf-documents/; classtype:trojan-activity; sid:2014575; rev:4; metadata:created_at 2012_04_16, updated_at 2012_04_16;)
` 

Name : **Potential Malicious PDF (EmbeddedFiles) improper case** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.didierstevens.com/2009/07/01/embedding-and-hiding-files-in-pdf-documents/

CVE reference : Not defined

Creation date : 2012-04-16

Last modified date : 2012-04-16

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013824
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.myftp.biz Domain"; flow:established,to_server; content:".myftp.biz|0d 0a|"; http_header; nocase; classtype:bad-unknown; sid:2013824; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.myftp.biz Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013846
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.ez-dns.com Domain"; flow:established,to_server; content:".ez-dns.com|0d 0a|"; http_header; classtype:bad-unknown; sid:2013846; rev:3; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.ez-dns.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013864
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dyndns-web.com Domain"; flow:to_server,established; content:".dyndns-web.com|0D 0A|";  http_header; classtype:bad-unknown; sid:2013864; rev:3; metadata:created_at 2011_11_07, updated_at 2011_11_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dyndns-web.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2011-11-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014479
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.3d-game.com Domain"; flow:established,to_server; content:".3d-game.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014479; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.3d-game.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014481
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.4irc.com Domain"; flow:established,to_server; content:".4irc.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014481; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.4irc.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014483
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.b0ne.com Domain"; flow:established,to_server; content:".b0ne.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014483; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.b0ne.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014485
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.bbsindex.com Domain"; flow:established,to_server; content:".bbsindex.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014485; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.bbsindex.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014487
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.chatnook.com Domain"; flow:established,to_server; content:".chatnook.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014487; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.chatnook.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014489
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.darktech.org Domain"; flow:established,to_server; content:".darktech.org|0D 0A|"; http_header; classtype:bad-unknown; sid:2014489; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.darktech.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014491
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.deaftone.com Domain"; flow:established,to_server; content:".deaftone.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014491; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.deaftone.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014495
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.effers.com Domain"; flow:established,to_server; content:".effers.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014495; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.effers.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014497
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.etowns.net Domain"; flow:established,to_server; content:".etowns.net|0D 0A|"; http_header; classtype:bad-unknown; sid:2014497; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.etowns.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014499
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.etowns.org Domain"; flow:established,to_server; content:".etowns.org|0D 0A|"; http_header; classtype:bad-unknown; sid:2014499; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.etowns.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014501
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.flnet.org Domain"; flow:established,to_server; content:".flnet.org|0D 0A|"; http_header; classtype:bad-unknown; sid:2014501; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.flnet.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014503
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.gotgeeks.com Domain"; flow:established,to_server; content:".gotgeeks.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014503; rev:3; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.gotgeeks.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014505
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.scieron.com Domain"; flow:established,to_server; content:".scieron.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014505; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.scieron.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014507
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.slyip.com Domain"; flow:established,to_server; content:".slyip.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2014507; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.slyip.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014509
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.slyip.net Domain"; flow:established,to_server; content:".slyip.net|0D 0A|"; http_header; classtype:bad-unknown; sid:2014509; rev:4; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.slyip.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014787
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.2288.org"; flow:established,to_server; content:".2288.org|0D 0A|"; http_header; classtype:misc-activity; sid:2014787; rev:5; metadata:created_at 2012_05_18, updated_at 2012_05_18;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.2288.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2012-05-18

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014789
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.6600.org"; flow:established,to_server; content:".6600.org|0D 0A|"; http_header; classtype:misc-activity; sid:2014789; rev:4; metadata:created_at 2012_05_18, updated_at 2012_05_18;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.6600.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2012-05-18

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014790
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.7766.org"; flow:established,to_server; content:".7766.org|0D 0A|"; http_header; classtype:misc-activity; sid:2014790; rev:6; metadata:created_at 2012_05_18, updated_at 2012_05_18;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.7766.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2012-05-18

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014791
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.8800.org"; flow:established,to_server; content:".8800.org|0D 0A|"; http_header; classtype:misc-activity; sid:2014791; rev:5; metadata:created_at 2012_05_18, updated_at 2012_05_18;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.8800.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2012-05-18

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014792
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.9966.org"; flow:established,to_server; content:".9966.org|0D 0A|"; http_header; classtype:misc-activity; sid:2014792; rev:5; metadata:created_at 2012_05_18, updated_at 2012_05_18;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.9966.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2012-05-18

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014819
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Packed Executable Download"; flow:established,to_client; content:"|0d 0a 0d 0a|MZ"; isdataat:100,relative; content:"This program "; distance:0; content:"PE|00 00|"; distance:0; content:!"data"; within:400; content:!"text"; within:400; content:!"rsrc"; within:400; classtype:misc-activity; sid:2014819; rev:3; metadata:created_at 2012_05_30, updated_at 2012_05_30;)
` 

Name : **Packed Executable Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-30

Last modified date : 2012-05-30

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014867
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a dns-stuff.com Domain *.dns-stuff.com"; flow:established,to_server; content:"dns-stuff.com|0d 0a|"; http_header; classtype:bad-unknown; sid:2014867; rev:3; metadata:created_at 2012_06_07, updated_at 2012_06_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to a dns-stuff.com Domain *.dns-stuff.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-06-07

Last modified date : 2012-06-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014906
`alert ftp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO .exe File requested over FTP"; flow:established,to_server; dsize:>10; content:"RETR"; depth:4; content:".exe|0d 0a|"; distance:0; pcre:"/^RETR\s+[^\r\n]+?\x2eexe\r?$/m"; classtype:policy-violation; sid:2014906; rev:2; metadata:created_at 2012_06_15, updated_at 2012_06_15;)
` 

Name : **.exe File requested over FTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-06-15

Last modified date : 2012-06-15

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014926
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PDF embedded in XDP file (Possibly Malicious)"; flow:established, to_client; content:"<xdp|3a|xdp"; nocase; fast_pattern; content:"<pdf"; nocase; distance:0; pcre:"/\<xdp\x3axdp(\s+[^\>]*)?\>((?!\<\/xdp[^\>]*\>).)*?\<pdf/si"; reference:url,blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp; classtype:misc-attack; sid:2014926; rev:3; metadata:created_at 2012_06_20, updated_at 2012_06_20;)
` 

Name : **PDF embedded in XDP file (Possibly Malicious)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp

CVE reference : Not defined

Creation date : 2012-06-20

Last modified date : 2012-06-20

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015004
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Compressed Executable SZDD Compress.exe Format Over HTTP"; flow:established,to_client; content:"|0d 0a 0d 0a|SZDD"; content:"PE|00 00|"; distance:0; reference:url,blog.fireeye.com/research/2012/07/inside-customized-threat.html#more; reference:url,www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html; classtype:bad-unknown; sid:2015004; rev:3; metadata:created_at 2012_07_03, updated_at 2012_07_03;)
` 

Name : **Compressed Executable SZDD Compress.exe Format Over HTTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blog.fireeye.com/research/2012/07/inside-customized-threat.html#more|url,www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html

CVE reference : Not defined

Creation date : 2012-07-03

Last modified date : 2012-07-03

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015016
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"ET INFO FTP STOR to External Network"; flow:established,to_server; content:"STOR "; depth:5; classtype:misc-activity; sid:2015016; rev:2; metadata:created_at 2012_07_03, updated_at 2012_07_03;)
` 

Name : **FTP STOR to External Network** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-03

Last modified date : 2012-07-03

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015561
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PDF Using CCITTFax Filter"; flow:established,to_client; content:"obj"; content:"<<"; within:4; content:"/CCITTFaxDecode"; distance:0; metadata: former_category INFO; reference:url,nakedsecurity.sophos.com/2012/04/05/ccittfax-pdf-malware/; reference:url,blog.fireeye.com/research/2012/07/analysis-of-a-different-pdf-malware.html#more; classtype:bad-unknown; sid:2015561; rev:2; metadata:created_at 2012_08_02, updated_at 2017_06_01;)
` 

Name : **PDF Using CCITTFax Filter** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,nakedsecurity.sophos.com/2012/04/05/ccittfax-pdf-malware/|url,blog.fireeye.com/research/2012/07/analysis-of-a-different-pdf-malware.html#more

CVE reference : Not defined

Creation date : 2012-08-02

Last modified date : 2017-06-01

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014149
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible URL List or Clickfraud URLs Delivered To Client"; flow:established,from_server; content:"|0d 0a 0d 0a|http|3a|//"; content:"|7C|http|3a|//"; distance:0; content:"|0D 0A|http|3a|//"; distance:0; content:"|7C|http|3a|//"; distance:0; classtype:trojan-activity; sid:2014149; rev:4; metadata:created_at 2012_01_23, updated_at 2012_01_23;)
` 

Name : **Possible URL List or Clickfraud URLs Delivered To Client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-01-23

Last modified date : 2012-01-23

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015707
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - document.createElement applet"; flow:established,to_client; file_data; content:"document.createElement"; nocase; content:"applet"; nocase; fast_pattern; within:10; classtype:misc-activity; sid:2015707; rev:2; metadata:created_at 2012_09_17, updated_at 2012_09_17;)
` 

Name : **JAVA - document.createElement applet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-17

Last modified date : 2012-09-17

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014520
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - Served Attached HTTP"; flow:to_client,established; content:"Content-Disposition"; nocase; http_header; content:"attachment"; nocase; http_header; file_data; content:"MZ"; within:2;  classtype:misc-activity; sid:2014520; rev:6; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - Served Attached HTTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015745
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE CheckRemoteDebuggerPresent (Used in Malware Anti-Debugging)"; flow:established,to_client; file_data; flowbits:isset,ET.http.binary; content:"CheckRemoteDebuggerPresent"; classtype:misc-activity; sid:2015745; rev:2; metadata:created_at 2012_09_28, updated_at 2012_09_28;)
` 

Name : **EXE CheckRemoteDebuggerPresent (Used in Malware Anti-Debugging)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-28

Last modified date : 2012-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015842
`alert udp $HOME_NET 5355 -> any any (msg:"ET INFO LLNMR query response to wpad"; content:"|80 00 00 01 00 01|"; offset:2; depth:6; content:"|04|wpad|00 00 01 00 01 04|wpad|00 00 01 00 01|"; distance:0; isdataat:7,relative; classtype:misc-activity; sid:2015842; rev:2; metadata:created_at 2012_10_24, updated_at 2012_10_24;)
` 

Name : **LLNMR query response to wpad** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-24

Last modified date : 2012-10-24

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015954
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PDF /FlateDecode and PDF version 1.0"; flow:established,from_server; file_data; content:"%PDF-1.0"; fast_pattern; within:8; content:"/FlateDecode"; distance:0; classtype:trojan-activity; sid:2015954; rev:2; metadata:created_at 2012_11_28, updated_at 2012_11_28;)
` 

Name : **PDF /FlateDecode and PDF version 1.0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-28

Last modified date : 2012-11-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015963
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO PHISH Generic - Bank and Routing"; flow:established,to_server; content:"POST"; http_method; content:"bank"; http_client_body; nocase; content:"routing"; http_client_body; nocase; metadata: former_category INFO; classtype:bad-unknown; sid:2015963; rev:3; metadata:created_at 2012_11_28, updated_at 2012_11_28;)
` 

Name : **PHISH Generic - Bank and Routing** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-28

Last modified date : 2012-11-28

Rev version : 3

Category : PHISHING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015994
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"ET INFO MySQL Database Query Version OS compile"; flow:to_server,established; content:"|03|"; offset:3; depth:4; content:"select |40 40|version_compile_os"; nocase; pcre:"/SELECT @@version_compile_os\s*?\x3b/i"; classtype:misc-activity; sid:2015994; rev:2; metadata:created_at 2012_12_05, updated_at 2012_12_05;)
` 

Name : **MySQL Database Query Version OS compile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-05

Last modified date : 2012-12-05

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016145
`alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO PTUNNEL OUTBOUND"; itype:8; icode:0; content:"|D5 20 08 80|"; depth:4; reference:url,github.com/madeye/ptunnel; reference:url,cs.uit.no/~daniels/PingTunnel/#protocol; classtype:protocol-command-decode; sid:2016145; rev:2; metadata:created_at 2013_01_03, updated_at 2013_01_03;)
` 

Name : **PTUNNEL OUTBOUND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,github.com/madeye/ptunnel|url,cs.uit.no/~daniels/PingTunnel/#protocol

CVE reference : Not defined

Creation date : 2013-01-03

Last modified date : 2013-01-03

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016146
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PTUNNEL INBOUND"; itype:0; icode:0; content:"|D5 20 08 80|"; depth:4; reference:url,github.com/madeye/ptunnel; reference:url,cs.uit.no/~daniels/PingTunnel/#protocol; classtype:protocol-command-decode; sid:2016146; rev:3; metadata:created_at 2013_01_03, updated_at 2013_01_03;)
` 

Name : **PTUNNEL INBOUND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,github.com/madeye/ptunnel|url,cs.uit.no/~daniels/PingTunnel/#protocol

CVE reference : Not defined

Creation date : 2013-01-03

Last modified date : 2013-01-03

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016304
`alert udp $HOME_NET 1900 -> any any (msg:"ET INFO UPnP Discovery Search Response vulnerable UPnP device 3"; content:"Portable SDK for UPnP devices"; pcre:"/^Server\x3a[^\r\n]*Portable SDK for UPnP devices(\/?\s*$|\/1\.([0-5]\..|8\.0.|(6\.[0-9]|6\.1[0-7])))/m"; reference:url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play; reference:url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf; reference:cve,2012-5958; reference:cve,2012-5959; classtype:successful-recon-limited; sid:2016304; rev:2; metadata:created_at 2013_01_29, updated_at 2013_01_29;)
` 

Name : **UPnP Discovery Search Response vulnerable UPnP device 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play|url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf|cve,2012-5958|cve,2012-5959

CVE reference : Not defined

Creation date : 2013-01-29

Last modified date : 2013-01-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016303
`alert udp $HOME_NET 1900 -> any any (msg:"ET INFO UPnP Discovery Search Response vulnerable UPnP device 2"; content:"Intel SDK for UPnP devices"; pcre:"/^Server\x3a[^\r\n]*Intel SDK for UPnP devices/mi"; reference:url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play; reference:url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf; reference:cve,2012-5958; reference:cve,2012-5959; classtype:successful-recon-limited; sid:2016303; rev:4; metadata:created_at 2013_01_29, updated_at 2013_01_29;)
` 

Name : **UPnP Discovery Search Response vulnerable UPnP device 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play|url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf|cve,2012-5958|cve,2012-5959

CVE reference : Not defined

Creation date : 2013-01-29

Last modified date : 2013-01-29

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016360
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - ClassID"; flow:established,to_client; file_data; content:"8AD9C840-044E-11D1-B3E9-00805F499D93"; classtype:misc-activity; sid:2016360; rev:2; metadata:created_at 2013_02_06, updated_at 2013_02_06;)
` 

Name : **JAVA - ClassID** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-06

Last modified date : 2013-02-06

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016361
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - ClassID"; flow:established,to_client; file_data; content:"CAFEEFAC-00"; content:"-FFFF-ABCDEFFEDCBA"; distance:7; within:18; classtype:misc-activity; sid:2016361; rev:2; metadata:created_at 2013_02_06, updated_at 2013_02_06;)
` 

Name : **JAVA - ClassID** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-06

Last modified date : 2013-02-06

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016404
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO MPEG Download Over HTTP (1)"; flow:established,to_client; file_data; content:"|00 00 01 ba|"; depth:4; flowbits:set,ET.mpeg.HTTP; flowbits:noalert; classtype:not-suspicious; sid:2016404; rev:3; metadata:created_at 2013_02_12, updated_at 2013_02_12;)
` 

Name : **MPEG Download Over HTTP (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-12

Last modified date : 2013-02-12

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016502
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Java Serialized Data via vulnerable client"; flow:established,from_server; flowbits:isset,ET.http.javaclient.vulnerable; file_data; content:"|ac ed|"; within:2; flowbits:set,et.exploitkitlanding; classtype:trojan-activity; sid:2016502; rev:2; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **Java Serialized Data via vulnerable client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016503
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Java Serialized Data"; flow:established,from_server; flowbits:isset,ET.http.javaclient; file_data; content:"|ac ed|"; within:2; flowbits:set,et.exploitkitlanding; classtype:trojan-activity; sid:2016503; rev:2; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **Java Serialized Data** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016505
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO file possibly containing Serialized Data file"; flow:to_client,established; file_data; content:"PK"; within:2; content:".serPK"; flowbits:isset,ET.http.javaclient.vulnerable; classtype:trojan-activity; sid:2016505; rev:2; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **file possibly containing Serialized Data file** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016494
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Serialized Java Applet (Used by some EKs in the Wild)"; flow:established,from_server; file_data; content:"<applet"; nocase; content:"object"; distance:0; nocase; pcre:"/^[\r\n\s]*=[\r\n\s]*[\x22\x27][^\x22\x27]+\.ser[\x22\x27]/Ri"; metadata: former_category INFO; classtype:trojan-activity; sid:2016494; rev:5; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **Serialized Java Applet (Used by some EKs in the Wild)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016538
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Executable Retrieved With Minimal HTTP Headers - Potential Second Stage Download"; flowbits:isset,min.gethttp; flow:established,to_client; file_data; content:"MZ"; within:2; content:"PE|00 00|"; distance:0; classtype:bad-unknown; sid:2016538; rev:3; metadata:created_at 2013_03_05, updated_at 2013_03_05;)
` 

Name : **Executable Retrieved With Minimal HTTP Headers - Potential Second Stage Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-05

Last modified date : 2013-03-05

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016646
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Acrobat Web Capture [8-9].0"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Acrobat Web Capture "; pcre:"/^[8-9]\.0/R"; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016646; rev:3; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Acrobat Web Capture [8-9].0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016647
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Adobe LiveCycle Designer ES 8.2"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Adobe LiveCycle Designer ES 8.2"; fast_pattern:11,20; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016647; rev:3; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Adobe LiveCycle Designer ES 8.2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016648
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Python PDF Library"; flow:from_server,established; file_data; flowbits:isset,ET.pdf.in.http; content:"Python PDF Library - http|3a|//pybrary.net/pyPdf/"; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016648; rev:3; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Python PDF Library** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016649
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Acrobat Distiller 9.0.0 (Windows)"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Acrobat Distiller 9.0.0 (Windows)"; fast_pattern:3,20; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016649; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Acrobat Distiller 9.0.0 (Windows)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016650
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Acrobat Distiller 6.0.1 (Windows)"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Acrobat Distiller 6.0.1 (Windows)"; fast_pattern:3,20; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016650; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Acrobat Distiller 6.0.1 (Windows)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016651
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator pdfeTeX-1.21a"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"pdfeTeX-1.21a"; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016651; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator pdfeTeX-1.21a** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016652
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Adobe Acrobat 9.2.0"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Adobe Acrobat 9.2.0"; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016652; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Adobe Acrobat 9.2.0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016653
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Old/Rare PDF Generator Adobe PDF Library 9.0"; flow:from_server,established; flowbits:isset,ET.pdf.in.http; file_data; content:"Adobe PDF Library 9.0"; reference:url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html; classtype:not-suspicious; sid:2016653; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)
` 

Name : **Old/Rare PDF Generator Adobe PDF Library 9.0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,carnal0wnage.attackresearch.com/2013/03/apt-pdfs-and-metadata-extraction.html

CVE reference : Not defined

Creation date : 2013-03-22

Last modified date : 2013-03-22

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016766
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PDF - Acrobat Enumeration - var PDFObject"; flow:established,to_client; file_data; content:"var PDFObject="; classtype:misc-activity; sid:2016766; rev:2; metadata:created_at 2013_04_17, updated_at 2013_04_17;)
` 

Name : **PDF - Acrobat Enumeration - var PDFObject** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-17

Last modified date : 2013-04-17

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016767
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - SCR in PKZip Compressed Data Download"; flow:established,to_client; file_data; content:"PK"; within:2; content:".scr"; fast_pattern:only; nocase; classtype:bad-unknown; sid:2016767; rev:3; metadata:created_at 2013_04_17, updated_at 2013_04_17;)
` 

Name : **EXE - SCR in PKZip Compressed Data Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-17

Last modified date : 2013-04-17

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016774
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET INFO Generic HTTP EXE Upload Inbound"; flow:established,to_server; content:"POST"; http_method; nocase; content:"MZ"; http_client_body; content:"|00 00 00 00|"; http_client_body; distance:0; content:"PE|00 00|"; http_client_body; fast_pattern; distance:0; classtype:misc-activity; sid:2016774; rev:2; metadata:created_at 2013_04_18, updated_at 2013_04_18;)
` 

Name : **Generic HTTP EXE Upload Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-18

Last modified date : 2013-04-18

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016775
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Generic HTTP EXE Upload Outbound"; flow:established,to_server; content:"POST"; http_method; nocase; content:"MZ"; http_client_body; content:"|00 00 00 00|"; http_client_body; distance:0; content:"PE|00 00|"; http_client_body; fast_pattern; distance:0; classtype:misc-activity; sid:2016775; rev:2; metadata:created_at 2013_04_18, updated_at 2013_04_18;)
` 

Name : **Generic HTTP EXE Upload Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-18

Last modified date : 2013-04-18

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016692
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS UA starting with Mozilla/7"; flow:established,to_server; content:"Mozilla/7"; depth:9; nocase; http_user_agent; classtype:bad-unknown; sid:2016692; rev:4; metadata:created_at 2013_04_01, updated_at 2013_04_01;)
` 

Name : **SUSPICIOUS UA starting with Mozilla/7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2013-04-01

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016694
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS UA starting with Mozilla/9"; flow:established,to_server; content:"Mozilla/9"; depth:9; nocase; http_user_agent; classtype:bad-unknown; sid:2016694; rev:4; metadata:created_at 2013_04_01, updated_at 2013_04_01;)
` 

Name : **SUSPICIOUS UA starting with Mozilla/9** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2013-04-01

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016825
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Possible CollectGarbage in base64 1"; flow:established,from_server; file_data; content:"Q29sbGVjdEdhcmJhZ2U"; metadata: former_category INFO; classtype:misc-activity; sid:2016825; rev:3; metadata:created_at 2013_05_06, updated_at 2013_05_06;)
` 

Name : **Suspicious Possible CollectGarbage in base64 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-06

Last modified date : 2013-05-06

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016826
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Possible CollectGarbage in base64 2"; flow:established,from_server; file_data; content:"NvbGxlY3RHYXJiYWdlK"; metadata: former_category INFO; classtype:misc-activity; sid:2016826; rev:3; metadata:created_at 2013_05_06, updated_at 2013_05_06;)
` 

Name : **Suspicious Possible CollectGarbage in base64 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-06

Last modified date : 2013-05-06

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016827
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Possible CollectGarbage in base64 3"; flow:established,from_server; file_data; content:"Db2xsZWN0R2FyYmFnZS"; metadata: former_category INFO; classtype:misc-activity; sid:2016827; rev:3; metadata:created_at 2013_05_06, updated_at 2013_05_06;)
` 

Name : **Suspicious Possible CollectGarbage in base64 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-06

Last modified date : 2013-05-06

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016880
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 0 User-Agent"; flow:established,to_server; content:"Windows NT 0"; nocase; http_user_agent;  classtype:trojan-activity; sid:2016880; rev:6; metadata:created_at 2013_05_20, updated_at 2013_05_20;)
` 

Name : **Suspicious Windows NT version 0 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-20

Last modified date : 2013-05-20

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016898
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious MSIE 10 on Windows NT 5"; flow:established,to_server; content:" MSIE 10.0|3b| Windows NT 5."; http_user_agent; fast_pattern:4,20; threshold: type limit,track by_src,count 2,seconds 60; classtype:trojan-activity; sid:2016898; rev:6; metadata:created_at 2013_05_21, updated_at 2013_05_21;)
` 

Name : **Suspicious MSIE 10 on Windows NT 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-21

Last modified date : 2013-05-21

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016921
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Mozilla UA with no Space after colon"; flow:established,to_server; content:"User-Agent|3a|Mozilla"; http_header; nocase; fast_pattern:only; threshold: type limit,track by_src,count 2,seconds 60; metadata: former_category INFO; classtype:trojan-activity; sid:2016921; rev:5; metadata:created_at 2013_05_23, updated_at 2017_10_18;)
` 

Name : **Suspicious Mozilla UA with no Space after colon** 

Attack target : Not defined

Description : Dupe with 2011800

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-05-23

Last modified date : 2017-10-18

Rev version : 5

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016985
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Executable Served From /tmp/ Directory - Malware Hosting Behaviour"; flow:established,to_server; content:"/tmp/"; http_uri; depth:5; content:".exe"; http_uri; distance:0; pcre:"/^\x2Ftmp\x2F.+\x2Eexe$/U"; classtype:bad-unknown; sid:2016985; rev:2; metadata:created_at 2013_06_06, updated_at 2013_06_06;)
` 

Name : **Executable Served From /tmp/ Directory - Malware Hosting Behaviour** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-06-06

Last modified date : 2013-06-06

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017080
`alert http any any -> any any (msg:"ET INFO HTTP POST contains pasa= in cleartext"; flow:established,to_server; content:"pasa="; http_client_body; pcre:"/pasa=(?!&)./Pi"; metadata: former_category INFO; classtype:policy-violation; sid:2017080; rev:2; metadata:created_at 2013_07_01, updated_at 2013_07_01;)
` 

Name : **HTTP POST contains pasa= in cleartext** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-01

Last modified date : 2013-07-01

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017081
`alert http any any -> any any (msg:"ET INFO HTTP URI contains pasa="; flow:established,to_server; content:"pasa="; http_uri; nocase; pcre:"/(?<=(\?|&))pasa=(?!&)./Ui"; metadata: former_category INFO; classtype:policy-violation; sid:2017081; rev:2; metadata:created_at 2013_07_01, updated_at 2013_07_01;)
` 

Name : **HTTP URI contains pasa=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-01

Last modified date : 2013-07-01

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017082
`alert http any any -> any any (msg:"ET INFO HTTP POST contains pasa form"; flow:established,to_server; content:"name=|22|pasa|22|"; http_client_body; metadata: former_category INFO; classtype:policy-violation; sid:2017082; rev:2; metadata:created_at 2013_07_01, updated_at 2013_07_01;)
` 

Name : **HTTP POST contains pasa form** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-01

Last modified date : 2013-07-01

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017127
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JJEncode Encoded Script"; flow:established,from_server; file_data; content:"$$$$|3a|(![]+|22 22|)["; pcre:"/^(?P<global_var>((?!(\]\,__\$\x3a\+\+)).)+)]\,__\$\x3a\+\+(?P=global_var)/R"; classtype:bad-unknown; sid:2017127; rev:2; metadata:created_at 2013_07_10, updated_at 2013_07_10;)
` 

Name : **JJEncode Encoded Script** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-10

Last modified date : 2013-07-10

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016504
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Serialized Data request"; flow:established,to_server; content:"Java/1."; http_user_agent; content:".ser"; http_uri; pcre:"/\.ser$/U"; classtype:bad-unknown; sid:2016504; rev:4; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **Serialized Data request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017197
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JNLP embedded file"; flow:established,to_client; file_data; content:"jnlp"; content:"PD94bWwgdmVyc2lvbj0"; distance:0; classtype:bad-unknown; sid:2017197; rev:3; metadata:created_at 2013_07_25, updated_at 2013_07_25;)
` 

Name : **JNLP embedded file** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-25

Last modified date : 2013-07-25

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017206
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 1"; flow:established,from_server; file_data; content:"|22|e|22|+|22|val|22|"; classtype:trojan-activity; sid:2017206; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017207
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 2"; flow:established,from_server; file_data; content:"|22|ev|22|+|22|al|22|"; classtype:trojan-activity; sid:2017207; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017208
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 3"; flow:established,from_server; file_data; content:"|22|e|22|+|22|v|22|+|22|al|22|"; classtype:trojan-activity; sid:2017208; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017209
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 4"; flow:established,from_server; file_data; content:"|22|e|22|+|22|v|22|+|22|a|22|+|22|l|22|"; classtype:trojan-activity; sid:2017209; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017210
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 5"; flow:established,from_server; file_data; content:"|22|ev|22|+|22|a|22|+|22|l|22|"; classtype:trojan-activity; sid:2017210; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017211
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 6"; flow:established,from_server; file_data; content:"|22|e|22|+|22|va|22|+|22|l|22|"; classtype:trojan-activity; sid:2017211; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017212
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 1"; flow:established,from_server; file_data; content:"|27|e|27|+|27|val|27|"; classtype:trojan-activity; sid:2017212; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017213
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 2"; flow:established,from_server; file_data; content:"|27|ev|27|+|27|al|27|"; classtype:trojan-activity; sid:2017213; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017214
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 3"; flow:established,from_server; file_data; content:"|27|eva|27|+|27|l|27|"; classtype:trojan-activity; sid:2017214; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017215
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 4"; flow:established,from_server; file_data; content:"|27|e|27|+|27|v|27|+|27|al|27|"; classtype:trojan-activity; sid:2017215; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017216
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 5"; flow:established,from_server; file_data; content:"|27|e|27|+|27|v|27|+|27|a|27|+|27|l|27|"; classtype:trojan-activity; sid:2017216; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017218
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 7"; flow:established,from_server; file_data; content:"|27|e|27|+|27|va|27|+|27|l|27|"; classtype:trojan-activity; sid:2017218; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017217
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String (Single Q) 6"; flow:established,from_server; file_data; content:"|27|ev|27|+|27|a|27|+|27|l|27|"; classtype:trojan-activity; sid:2017217; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String (Single Q) 6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017219
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Eval String 7"; flow:established,from_server; file_data; content:"|22|eva|22|+|22|l|22|"; classtype:trojan-activity; sid:2017219; rev:2; metadata:created_at 2013_07_26, updated_at 2013_07_26;)
` 

Name : **Obfuscated Eval String 7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-26

Last modified date : 2013-07-26

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017220
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 1"; flow:established,from_server; file_data; content:"|27|s|27|+|27|plit|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017220; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017221
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 2"; flow:established,from_server; file_data; content:"|27|sp|27|+|27|lit|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017221; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017222
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 3"; flow:established,from_server; file_data; content:"|27|s|27|+|27|p|27|+|27|lit|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017222; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017223
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 4"; flow:established,from_server; file_data; content:"|27|spl|27|+|27|it|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017223; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017224
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 5"; flow:established,from_server; file_data; content:"|27|sp|27|+|27|l|27|+|27|it|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017224; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017225
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 6"; flow:established,from_server; file_data; content:"|27|s|27|+|27|pl|27|+|27|it|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017225; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017226
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 7"; flow:established,from_server; file_data; content:"|27|s|27|+|27|p|27|+|27|l|27|+|27|it|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017226; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017227
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 8"; flow:established,from_server; file_data; content:"|27|spli|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017227; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 8** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017228
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 9"; flow:established,from_server; file_data; content:"|27|sp|27|+|27|l|27|+|27|i|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017228; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 9** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017229
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 10"; flow:established,from_server; file_data; content:"|27|sp|27|+|27|li|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017229; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 10** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017230
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 11"; flow:established,from_server; file_data; content:"|27|spl|27|+|27|i|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017230; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 11** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017231
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 12"; flow:established,from_server; file_data; content:"|27|s|27|+|27|pli|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017231; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 12** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017232
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Single Q) 13"; flow:established,from_server; file_data; content:"|27|s|27|+|27|p|27|+|27|l|27|+|27|i|27|+|27|t|27|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017232; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Single Q) 13** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017233
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 1"; flow:established,from_server; file_data; content:"|22|s|22|+|22|plit|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017233; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017234
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 2"; flow:established,from_server; file_data; content:"|22|sp|22|+|22|lit|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017234; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017235
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 3"; flow:established,from_server; file_data; content:"|22|s|22|+|22|p|22|+|22|lit|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017235; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017236
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 4"; flow:established,from_server; file_data; content:"|22|spl|22|+|22|it|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017236; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017237
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 5"; flow:established,from_server; file_data; content:"|22|sp|22|+|22|l|22|+|22|it|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017237; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017238
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 6"; flow:established,from_server; file_data; content:"|22|s|22|+|22|pl|22|+|22|it|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017238; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017239
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 7"; flow:established,from_server; file_data; content:"|22|s|22|+|22|p|22|+|22|l|22|+|22|it|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017239; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017240
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 8"; flow:established,from_server; file_data; content:"|22|spli|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017240; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 8** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017241
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 9"; flow:established,from_server; file_data; content:"|22|sp|22|+|22|l|22|+|22|i|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017241; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 9** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017242
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 10"; flow:established,from_server; file_data; content:"|22|sp|22|+|22|li|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017242; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 10** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017243
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 11"; flow:established,from_server; file_data; content:"|22|spl|22|+|22|i|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017243; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 11** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017244
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 12"; flow:established,from_server; file_data; content:"|22|s|22|+|22|pli|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017244; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 12** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017245
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated Split String (Double Q) 13"; flow:established,from_server; file_data; content:"|22|s|22|+|22|p|22|+|22|l|22|+|22|i|22|+|22|t|22|"; nocase; flowbits:set,ET.JS.Obfus.Func; classtype:bad-unknown; sid:2017245; rev:2; metadata:created_at 2013_07_29, updated_at 2013_07_29;)
` 

Name : **Obfuscated Split String (Double Q) 13** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-29

Last modified date : 2013-07-29

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017294
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Adobe PKG Download Flowbit Set"; flow:established,to_server; content:"pkg"; http_uri; content:"Host|3a 20|platformdl.adobe.com|0d 0a|"; http_header; nocase; flowbits:set,ET.Adobe.Site.Download; flowbits:noalert; classtype:misc-activity; sid:2017294; rev:3; metadata:created_at 2013_08_06, updated_at 2013_08_06;)
` 

Name : **Adobe PKG Download Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-06

Last modified date : 2013-08-06

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017282
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Microsoft Script Encoder Encoded File"; flow:established,from_server; file_data; content:"#@~^"; within:4; classtype:trojan-activity; sid:2017282; rev:3; metadata:created_at 2013_08_06, updated_at 2013_08_06;)
` 

Name : **Microsoft Script Encoder Encoded File** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-06

Last modified date : 2013-08-06

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017334
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Reassigned Eval Function 1"; flow:established,from_server; file_data; content:"=(eval)|3b|"; metadata: former_category INFO; classtype:bad-unknown; sid:2017334; rev:3; metadata:created_at 2013_08_15, updated_at 2013_08_15;)
` 

Name : **SUSPICIOUS Reassigned Eval Function 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-15

Last modified date : 2013-08-15

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017335
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Reassigned Eval Function 2"; flow:established,from_server; file_data; content:"=[|22|eval|22|]|3b|"; metadata: former_category INFO; classtype:bad-unknown; sid:2017335; rev:3; metadata:created_at 2013_08_15, updated_at 2013_08_15;)
` 

Name : **SUSPICIOUS Reassigned Eval Function 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-15

Last modified date : 2013-08-15

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017336
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Reassigned Eval Function 3"; flow:established,from_server; file_data; content:"=[|27|eval|27|]|3b|"; metadata: former_category INFO; classtype:bad-unknown; sid:2017336; rev:3; metadata:created_at 2013_08_15, updated_at 2013_08_15;)
` 

Name : **SUSPICIOUS Reassigned Eval Function 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-15

Last modified date : 2013-08-15

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017342
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Iframe For IP Address Site"; flow:established,to_client; file_data; content:"iframe src=|22|http|3A|//"; nocase; distance:0; pcre:"/^\d{1,3}\x2E\d{1,3}\x2E\d{1,3}\x2E\d{1,3}[^\r\n]*\x3C\x2Fiframe\x3E/Ri"; classtype:bad-unknown; sid:2017342; rev:3; metadata:created_at 2013_08_19, updated_at 2013_08_19;)
` 

Name : **Iframe For IP Address Site** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-19

Last modified date : 2013-08-19

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017363
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO InetSim Response from External Source Possible SinkHole"; flow:from_server,established; content:"Server|3a| INetSim HTTP Server"; http_header; classtype:bad-unknown; sid:2017363; rev:2; metadata:created_at 2013_08_21, updated_at 2013_08_21;)
` 

Name : **InetSim Response from External Source Possible SinkHole** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-21

Last modified date : 2013-08-21

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017364
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPCIOUS Non-standard base64 charset used for encoding"; flow:established,from_server; file_data; content:" & 15) << 4)"; fast_pattern; content:"(|22|"; content:!"|22|"; within:65; content:"|22|"; distance:65; within:1; content:!"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; distance:-66; within:62; content:!"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; distance:-66; within:62; content:!"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; distance:-66; within:62; content:!"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; distance:-66; within:62; content:!"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"; distance:-66; within:62; content:!"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; distance:-66; within:62; flowbits:set,et.exploitkitlanding; classtype:bad-unknown; sid:2017364; rev:7; metadata:created_at 2013_08_21, updated_at 2013_08_21;)
` 

Name : **SUSPCIOUS Non-standard base64 charset used for encoding** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-21

Last modified date : 2013-08-21

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017457
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Java request to UNI.ME Domain Set 1"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/^Host\:[^\r\n]+?\.(?:c(?:o(?:l(?:leg(?:e(?:(?:confidential|-station|prowler)\.net|s?explained\.com)|iate(?:explained|info)\.com)|(?:o(?:rado-springs-jobs|nexplained)|umnexplore)\.com)|m(?:p(?:uter(?:explained\.com|themes\.net)|assiondefinition\.com)|m(?:oditylingerie|unesinfo|ercekid)\.com)|n(?:ce(?:rtparis\.net|ptsets\.com)|trolwedding\.com)|(?:(?:rnell|upon)explained|peguide)\.com|7\.us)|a(?:(?:(?:mpaign|talog|det)explained|n(?:cersexplained|adadaycore)|p(?:itali[sz]eguide|ricornhi)|b(?:leexplained|indynamic))\.com|r(?:(?:tograph(?:yanalysis|erwhat)|cinomas?explained|scratch-remover|eblack)\.com|insurance-compare\.net)|ce\.us)|h(?:(?:a(?:r(?:med-episodes|les-proxy|tpixel)|p(?:elsinfo|terball)|nnelexplained)|ristmas(?:gift-ideas|motion)|inesenewyearboom|eckingwatch)\.com|(?:orizo|urros)\.es)|(?:e(?:l(?:lularexplained|iac-diet)|ntigrade(?:explained|info))|(?:li(?:nical|ck)|ustomized)explained|r(?:uiseshipdating|iticsmart)|pu-benchmark|nc-cs)\.com|8\.biz|z\.cc)|a(?:(?:ll(?:about(?:(?:(?:collegi|gradu)at|yal)e|s(?:eminary|tudent)|(?:facul|varsi)ty|bestsellers|academic|teaching|harvard|ucla|pro)|babyours)|n(?:(?:tipodesbi|alyzelan)d|onymous-film)|(?:mericas-nexttopmode|gentsbal)l|r(?:chitectureice|lingtonwriter)|c(?:ademicexplaine|tionmo)d|ero(?:flotinfo|bicfund))\.com|u(?:(?:toma(?:tedexplained|kers24)|stralia-airlines|xiliaryverb)\.com|di(?:t(?:jewellery\.com|report\.net)|o-planet\.com))|p(?:(?:rilfools(?:hotel|spin)|ple-airport)\.com|[fh]i\.biz)|ir(?:(?:bnb-coupon|waysinfo)\.com|portshuttleseattle\.net)|v(?:enue(?:domain|hello)\.com|li\.biz)|\.e\.gy)|b(?:(?:a(?:c(?:helorexplained|kpackscope)|by(?:online-shop|revision)|(?:rcelonarea|ggagecoo)l|s(?:icexplained|escope)|ttle-field-3)|e(?:(?:st-hoteldeal|er-calorie|t-award)s|nefitexplained)|u(?:y-invite|dgetyep)|logger-com)\.com|r(?:(?:o(?:adbandinternet-providers|king(?:explained|guide))|unomarsalbum|yan-college)\.com|ea(?:st(?:cancertattoos\.net|explained\.com)|dmachine-recipes\.com))|o(?:(?:(?:om(?:ing|s)|nd)explained|tany(?:explained|info)|dybuildingdomains|rrowings?24)\.com|stoncolleges\.net)|irthcertificatetemplate\.net|3g\.biz)|d(?:e(?:(?:(?:(?:benture|posit)explaine|alershipislan)d|n(?:guefevertreatment|verhowto)|ductguide|veloptea)\.com|(?:xterstreaming|ciduoustrees)\.net)|o(?:(?:ctorate(?:s?explained|info)|llar-converter|gwalking-jobs|texplained|mainsknow)\.com|wnload(?:starcraft|-films|ubuntu)\.net)|(?:a(?:ncecentralsonglist|rtmouthexplained)|na-replication|hcp-server|vd-codec|rivewww)\.com|i(?:(?:s(?:count|ease)explained|nnerparty-recipes|walifile)\.com|rect-golf\.net))|e(?:(?:a(?:r(?:fulexplained|th-clinic)|sy(?:-costumes|repayment))|conomic(?:save|24))\.com|\.gy)|4(?:(?:4qs|h5)\.com|[jp]\.org|ql\.biz)|3(?:vt\.info|gb\.biz|q\.org)|2(?:eat\.com|sf\.biz|u\.se)|8(?:c1\.net|x\.biz)|7(?:c\.org|p\.biz)|11r\.(?:biz|us))(\x3a\d{1,5})?\r?$/Hmi"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2017457; rev:3; metadata:created_at 2013_09_13, updated_at 2013_09_13;)
` 

Name : **SUSPICIOUS Java request to UNI.ME Domain Set 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-13

Last modified date : 2013-09-13

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017458
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Java request to UNI.ME Domain Set 2"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/^Host\:[^\r\n]+?\.(?:f(?:(?:a(?:c(?:ultyexplained|e-bok)|(?:ncy-font|ke-nail)s|ir(?:explained|fuse)|shion-wallpaper|lterguide)|i(?:nanc(?:i(?:al|ng)explained|epets)|rm(?:explained|s24)|lter-coffee)|o(?:r(?:umexplained|ecastbooks|ceestate)|x-drama)|udaninfo)\.com|re(?:e(?:-(?:(?:(?:foodcoupon|angrybird)s|s(?:oundclips|tock)|photoeditor)\.com|music-download\.net)|(?:p(?:owerpointthem|roduct-sampl)es|dom-ofspeech)\.com|fileconverter\.net)|snoever\.com)|l(?:a(?:shplayerdownload\.net|tbelly-diet\.com)|oridaunemploymentclaim\.com|v-downloader\.net)|e(?:rtility-calculator\.net|stivalexplained\.com)|b(?:-smileys\.com|skins\.net))|l(?:(?:i(?:n(?:k(?:explained|master)|colnsbirthdaytea)|(?:ability|ver)explained|(?:berty-saf|ftmov)e|stings(?:biz|red)|teraturemulti)|u(?:ng(?:explained|abscess)|ggageboom)|o(?:cationssecure|ndon-riots|gback))\.com|e(?:(?:a(?:singexplained|ther-trousers)|(?:edsunited-new|d-candle)s|cturer(?:explained|info)|nd(?:ing|er)explained|isure-diving)\.com|u(?:kemiaexplained\.com|e\.biz)|tup\.org)|a(?:guay\.(?:com|es)|-gazzetta\.com)|6\.org)|i(?:n(?:s(?:(?:ur(?:er(?:s(?:explained|24)|explained)|ancesexplained)|ide-film)\.com|(?:pection-camera|taflex)\.net)|d(?:e(?:pendenceday(?:portal|realty)|mnityexplained)\.com|ividual-healthinsurance\.net)|t(?:er(?:estexplained\.com|trigo\.net)|ranet(?:explained|pm)\.com)|(?:(?:vestment|centive)explained|expensivehyper)\.com|f(?:ections?explained\.com|o\.se))|(?:(?:mmersio|sd)nexplained|ronmancom|pone-5)\.com|i(?:nkai|lg)\.biz)|m(?:(?:e(?:tropolis(?:(?:cruis|fac|mov)e|pixel)|(?:lanoma|dical)explained|r(?:idiantotal|cedes-cls)|ntal-healthjobs|morialdaycon|ssenger-mac|ansgift)|i(?:ami(?:-holidays|what)|di-editor)|baexplained)\.com|a(?:r(?:(?:tial-empires|ket-hq)\.com|iogames-online\.net)|n(?:(?:agejoin|ualzap)\.com|ipal-university\.net)|(?:lignanthypertension|gazinedownload)\.net|s(?:on(?:wave|car)|tersexplained)\.com|c2\.org))|e(?:(?:s(?:ta(?:tes(?:mob|fx)|blishstyle)|lexplained)|mploy(?:e(?:eexplained|r24)|mentexplained))\.com|n(?:(?:(?:gagement-photo|able-cookie)s|rollexplained)\.com|trepreneur-ideas\.net)|x(?:(?:(?:hibition|po)explained|ecutive-decision)\.com|tremedeal\.net)|l(?:ect(?:ronicexplained|orate123)\.com|guay\.(?:com|es))|q(?:uityexplained\.com|8\.biz))|g(?:(?:o(?:a(?:d(?:minister|vertize|just)|cademic|llocate)|(?:thic-literatur|handl)e|(?:bailou|conduc)t|govern)|r(?:a(?:duate(?:explained|sinfo)|ndparentsdayplan)|oceryexplained|4)|ym(?:glas|car)s|m[69])\.com|a(?:(?:(?:llaudet|te)explained|mevelocity|rnerguide)\.com|511\.net)|cwsa\.org)|h(?:o(?:(?:me(?:made-biscuits|pageexplained)|(?:nours|tline|using)explained|6)\.com|stel-barcelona\.net)|a(?:r(?:dback(?:city|yoga)|vardexplained)|n(?:dlechange|ukkahbio)|lloweenorange)\.com|y(?:perthyroidsymptoms\.net|d\.me)|ellokittypictures\.net)|j(?:(?:o(?:urnalism(?:explained|info)|hn-grisham|ker-tattoo)|query-examples)\.com|a(?:cksonvillepath\.com|vacollection\.net)|(?:vvg|6)\.org)|k(?:ilometersreach|udosexplained|jyg)\.com)(\x3a\d{1,5})?\r?$/Hmi"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2017458; rev:3; metadata:created_at 2013_09_13, updated_at 2013_09_13;)
` 

Name : **SUSPICIOUS Java request to UNI.ME Domain Set 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-13

Last modified date : 2013-09-13

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017459
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Java request to UNI.ME Domain Set 3"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/^Host\:[^\r\n]+?\.(?:p(?:r(?:o(?:pert(?:ies(?:-forsale\.net|winters\.com)|y-(?:singapore|rental)\.net)|(?:fessors|state)explained\.com)|e(?:miums(?:e(?:xplained|ek)|guide)|(?:acher|cinct|late)sinfo|pexplained)\.com|i(?:va(?:te(?:car-sales|explained)\.com|do\.info)|nceton\.me))|e(?:(?:n(?:sionexplained|thousepal|cetruck)|diatricsexplained)\.com|rsonal(?:trainer-certification\.net|-injuryclaims\.com)|tardo\.es)|o(?:(?:wer(?:borrowings?|repayment|debts)|rt(?:land-holidays|alexplained)|intexplained|litical24)\.com|kertexas-holdem\.net)|a(?:(?:ss(?:engersinfo|agepix)|ge(?:explained|as)|cemaker-surgery|ttinson-robert|rk-edu)\.com|loaltocollege\.net)|(?:u(?:blicationgift|pils?info)|ickups(?:articles|gen)|neumoniaexplained|sychologyquotes|lus-sign)\.com|h(?:o(?:toedit(?:orfreedownload\.net|ingsite\.com)|neexplained\.com)|pbb-themes\.com|yscology\.net)|cbp\.net|9\.org)|o(?:n(?:line(?:(?:(?:f(?:o(?:ster|rce)|irstborn|raternal|ulltime)|b(?:r(?:idegroom|owse)|oxoffice)|e(?:(?:valuat|xpress)e|fficient)|-(?:collegecourse|radiostation)|d(?:escendant|aughter|iscusse)|v(?:illage|acant)|re(?:sidence|al))s|c(?:(?:r(?:iti(?:c(?:ize|al)|que)|ew)|o(?:nsider|usin)|a(?:pture|meo)|elluloid)s|ha(?:racters|teau))|a(?:(?:(?:vailabl|doptiv|llianc|pprais)e|ss(?:esse|ay)|unt)s|n(?:(?:cestor|alyze)s|imated)|way)|per(?:sonal-trainer|manents))\.com|mediaconverter\.net)|e-lyrics\.com|amia\.biz)|(?:ver(?:seasexplained|drawnreal)|(?:wnership|ffline)explained|cean(?:ic-cable|you)|rphanagesinfo|klahomafuse)\.com|a(?:klandour\.com|pg\.org))|r(?:e(?:(?:s(?:idenc(?:e(?:attorney|dating|cook|food)|yexplained)|erves(?:development|core))|(?:c(?:o(?:ver(?:ing|ed)|up)|laim)guid|laxationhyp|bateventur)e|g(?:i(?:on(?:private|mentor)|stercommunity)|ainguide)|t(?:r(?:ainingexplained|ieveguide)|ailexplained)|motecontrol-helicopter|viewwinters|payment24)\.com|alestate-perth\.net)|(?:a(?:cetracksinfo|veexplained|iserepair|tetask)|ising-antivirus|bnnetwork)\.com|o(?:(?:o(?:m(?:sfootball|mateco)|fcute)|admodern)\.com|yallondonhospital\.net))|s(?:(?:o(?:(?:lventsourc|ftenguid)e|urceexplained|cietiesinfo|ng-india)|a(?:n(?:antoniosource|diegodiscover)|l(?:aryexplaine|euploa)d)|ta(?:nford(?:explained|info)|(?:bilis|v)eguide|r-treck)|p(?:ecialtyexplained|iralwatch|orts-tab)|ch(?:oolexplained|eduleedu)|ites?explained)\.com|e(?:(?:minar(?:y(?:explained|info)|explained)|c(?:(?:urities|tor)explained|what)|aworld-coupons)\.com|rvertransfer\.net)|m(?:ier\.org|oz\.us)|hellgascard\.net|gba\.biz)|m(?:o(?:(?:t(?:oristsinfo|iveshare)|ntre-breitling|dernexplained|squesinfo)\.com|hamed\.me)|(?:y(?:borrowings|-husband)|ultimediaexplained|inistriesinfo)\.com|mcd\.us)|n(?:(?:a(?:ming(?:mac|our)|uticalfit|vigateadd)|e(?:tworkexplained|w-college))\.com|8\.biz))(\x3a\d{1,5})?\r?$/Hmi"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2017459; rev:3; metadata:created_at 2013_09_13, updated_at 2013_09_13;)
` 

Name : **SUSPICIOUS Java request to UNI.ME Domain Set 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-13

Last modified date : 2013-09-13

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017460
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Java request to UNI.ME Domain Set 4"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/^Host\:[^\r\n]+?\.(?:t(?:e(?:(?:l(?:e(?:phoneexplained|comsguide)|learth)|n(?:ured(?:explained|info)|nis-ranking))\.com|mp(?:l(?:ates-gratis\.com|ecollege\.net)|converter\.net)|a(?:ching(?:-certificate\.net|explained\.com)|m\.pro))|r(?:a(?:(?:(?:nsferbyt|de-)e|in(?:eesinf|ge)o|mray)\.com|vel(?:insurance-comparison\.net|agentnerd\.com))|e(?:k-bicycles|nd-online)\.net|uckstool\.com|onco\.es)|(?:o(?:wn(?:housepic|study|euro|meta)|(?:tal-tool|memap)s|pgamebook|olboxsol)|u(?:mors?explained|lsatrain|rn-ons)|attoo-websites|ype-racer|wainfo)\.com|h(?:(?:anksgivinggaming|riftexplained)\.com|e(?:sis-examples\.com|atreparis\.net))|i(?:mezonevendor\.com|dl\.net)|cmn\.biz)|w(?:e(?:b(?:(?:b(?:estseller|ailout)|administer)\.com|site(?:downloader\.net|explained\.com)|developertoolbar\.net)|(?:l(?:lesley|fare)explained|akenguide)\.com)|or(?:th(?:voice|war)\.com|ld-records\.net)|ater(?:front-property\.net|-plants\.com)|(?:riterpics|hoiscan)\.com|pbh\.org|sse\.us)|s(?:(?:t(?:ud(?:ent(?:financecontact|s?explained)|yexplained)|r(?:eetmaphub|ongat)|patricksweightloss|onewhat)|wissairinfo)\.com|u(?:(?:mmertimelyrics|nset-wallpaper|per-committee|itegraphic)\.com|b\.(?:name|cat|es)))|v(?:(?:i(?:llage(?:(?:in|na)no|crystal)|deo(?:-mediaset|explained)|ta(?:minssms|lwow)|rtualexplained)|o(?:lumesynergy|ucheragent|ters24)|a(?:rsityexplained|lentinesproxy)|entureexplained)\.com|qtel\.net|f1\.us)|u(?:n(?:i(?:versityexplained\.com|nstalltool\.net|\.me)|(?:(?:secured|am)explained|ravelguide)\.com|limited-web-hosting\.net)|(?:cla(?:explained|info)|s-inflation|alinfo|zdom)\.com|[04]\.org)|y(?:(?:o(?:u(?:ngstersinfo|rbroking)|mkippursocial)|(?:eshiva|ale)explained|vxs)\.com|nna\.biz)|zwr\.org)(\x3a\d{1,5})?\r?$/Hmi"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2017460; rev:3; metadata:created_at 2013_09_13, updated_at 2013_09_13;)
` 

Name : **SUSPICIOUS Java request to UNI.ME Domain Set 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-13

Last modified date : 2013-09-13

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017499
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Probably Evil Long Unicode string only string and unescape 1"; flow:established,from_server; file_data; content:"unescape"; content:"|22|%u"; content:!"|22|"; within:120; pcre:"/^[a-f0-9]{4}([\%\\]u[a-f0-9]{4}){20}/Ri"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2017499; rev:2; metadata:created_at 2013_09_20, updated_at 2013_09_20;)
` 

Name : **Probably Evil Long Unicode string only string and unescape 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-20

Last modified date : 2013-09-20

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017500
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Probably Evil Long Unicode string only string and unescape 2"; flow:established,from_server; file_data; content:"unescape"; content:"|27|%u"; nocase; content:!"|27|"; within:120; pcre:"/^[a-f0-9]{4}([\%\\]u[a-f0-9]{4}){20}/Ri"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2017500; rev:2; metadata:created_at 2013_09_20, updated_at 2013_09_20;)
` 

Name : **Probably Evil Long Unicode string only string and unescape 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-20

Last modified date : 2013-09-20

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017501
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Probably Evil Long Unicode string only string and unescape 3"; flow:established,from_server; file_data; content:"unescape"; content:"|22 5f|u"; nocase; pcre:"/^[a-f0-9]{4}([\%\\]u[a-f0-9]{4}){20}/Ri"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2017501; rev:2; metadata:created_at 2013_09_20, updated_at 2013_09_20;)
` 

Name : **Probably Evil Long Unicode string only string and unescape 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-20

Last modified date : 2013-09-20

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017502
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Probably Evil Long Unicode string only string and unescape 3"; flow:established,from_server; file_data; content:"unescape"; content:"|27 5f|u"; nocase; content:!"|27|"; within:100; pcre:"/^[a-f0-9]{4}([\%\\]u[a-f0-9]{4}){20}/Ri"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2017502; rev:2; metadata:created_at 2013_09_20, updated_at 2013_09_20;)
` 

Name : **Probably Evil Long Unicode string only string and unescape 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-20

Last modified date : 2013-09-20

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017504
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO DRIVEBY Generic - *.com.exe HTTP Attachment"; flow:established,to_client; content:".com.exe"; nocase; http_header; file_data; content:"MZ"; within:2; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2017504; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2013_09_20, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Generic - *.com.exe HTTP Attachment** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-20

Last modified date : 2016-07-01

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017565
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated fromCharCode"; flow:established,from_server; file_data; content:"|22|f"; nocase; content:!"romCharcode"; nocase; within:11; pcre:"/^(?:\x22\s*?\+\s*?\x22)?r(?:\x22\s*?\+\s*?\x22)?o(?:\x22\s*?\+\s*?\x22)?m(?:\x22\s*?\+\s*?\x22)?C(?:\x22\s*?\+\s*?\x22)?h(?:\x22\s*?\+\s*?\x22)?a(?:\x22\s*?\+\s*?\x22)?r(?:\x22\s*?\+\s*?\x22)?c(?:\x22\s*?\+\s*?\x22)?o(?:\x22\s*?\+\s*?\x22)?d(?:\x22\s*?\+\s*?\x22)?e/Ri"; classtype:bad-unknown; sid:2017565; rev:4; metadata:created_at 2013_10_07, updated_at 2013_10_07;)
` 

Name : **Obfuscated fromCharCode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-10-07

Last modified date : 2013-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017566
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Obfuscated fromCharCode"; flow:established,from_server; file_data; content:"|27|f"; nocase; content:!"romCharcode"; nocase; within:11; pcre:"/^(?:\x27\s*?\+\s*?\x27)?r(?:\x27\s*?\+\s*?\x27)?o(?:\x27\s*?\+\s*?\x27)?m(?:\x27\s*?\+\s*?\x27)?C(?:\x27\s*?\+\s*?\x27)?h(?:\x27\s*?\+\s*?\x27)?a(?:\x27\s*?\+\s*?\x27)?r(?:\x27\s*?\+\s*?\x27)?c(?:\x27\s*?\+\s*?\x27)?o(?:\x27\s*?\+\s*?\x27)?d(?:\x27\s*?\+\s*?\x27)?e/Ri"; classtype:bad-unknown; sid:2017566; rev:5; metadata:created_at 2013_10_07, updated_at 2013_10_07;)
` 

Name : **Obfuscated fromCharCode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-10-07

Last modified date : 2013-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017637
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Java File Sent With X-Powered By HTTP Header - Common In Exploit Kits"; flow:established,to_client; content:"Content-Type|3A| application/java-archive"; http_header; fast_pattern:25,13; content:"X-Powered-By|3A| PHP/"; http_header; file_data; content:"PK"; within:2; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2017637; rev:2; metadata:created_at 2013_10_28, updated_at 2013_10_28;)
` 

Name : **Java File Sent With X-Powered By HTTP Header - Common In Exploit Kits** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-10-28

Last modified date : 2013-10-28

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017669
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Zip File"; flow:established,from_server; file_data; content:"PK|03 04|"; within:4; flowbits:set,et.http.PK; flowbits:noalert; classtype:misc-activity; sid:2017669; rev:5; metadata:created_at 2013_11_06, updated_at 2013_11_06;)
` 

Name : **Zip File** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-11-06

Last modified date : 2013-11-06

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017748
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Java Downloading Archive flowbit no alert"; flow:established,from_server; flowbits:isset,ET.http.javaclient; file_data; content:"PK"; within:2; flowbits:set,et.JavaArchiveOrClass; flowbits:noalert; classtype:misc-activity; sid:2017748; rev:6; metadata:created_at 2013_11_25, updated_at 2013_11_25;)
` 

Name : **Java Downloading Archive flowbit no alert** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-11-25

Last modified date : 2013-11-25

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017749
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Java Downloading Class flowbit no alert"; flow:established,from_server; flowbits:isset,ET.http.javaclient; file_data; content:"|CA FE BA BE|"; within:4; flowbits:set,et.JavaArchiveOrClass; flowbits:noalert; classtype:misc-activity; sid:2017749; rev:6; metadata:created_at 2013_11_25, updated_at 2013_11_25;)
` 

Name : **Java Downloading Class flowbit no alert** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-11-25

Last modified date : 2013-11-25

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017884
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - ZIP file with .exe filename inside (Inbound)"; flow:established,to_server; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(5leG|LmV4|uZXhl)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017884; rev:5; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - ZIP file with .exe filename inside (Inbound)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 5

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017885
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - RAR file with .exe filename inside"; flow:established; content:"|0D 0A 0D 0A|UmFyI"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(5leG|LmV4|uZXhl)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017885; rev:5; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - RAR file with .exe filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 5

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017887
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - ZIP file with .com filename inside"; flow:established; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(uY29t|5jb2|LmNvb)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017887; rev:2; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - ZIP file with .com filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017888
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - RAR file with .com filename inside"; flow:established; content:"|0D 0A 0D 0A|UmFyI"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(uY29t|5jb2|LmNvb)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017888; rev:2; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - RAR file with .com filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017889
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - ZIP file with .scr filename inside"; flow:established; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(LnNjc|Euc2Ny|S5zY3)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017889; rev:2; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - ZIP file with .scr filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017890
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - RAR file with .scr filename inside"; flow:established; content:"|0D 0A 0D 0A|UmFyI"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(LnNjc|Euc2Ny|S5zY3)/R"; metadata: former_category INFO; classtype:bad-unknown; sid:2017890; rev:2; metadata:created_at 2013_12_19, updated_at 2013_12_19;)
` 

Name : **SUSPICIOUS SMTP EXE - RAR file with .scr filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2013-12-19

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017909
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO suspicious - uncompressed pack200-ed JAR"; flow:established,from_server; flowbits:isset,ET.http.javaclient; file_data; content:"|ca fe d0 0d|"; depth:4; flowbits:set,et.exploitkitlanding; metadata: former_category INFO; classtype:trojan-activity; sid:2017909; rev:3; metadata:created_at 2013_12_30, updated_at 2013_12_30;)
` 

Name : **suspicious - uncompressed pack200-ed JAR** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-30

Last modified date : 2013-12-30

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017910
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO suspicious - gzipped file via JAVA - could be pack200-ed JAR"; flow:established,from_server; flowbits:isset,ET.http.javaclient; file_data; content:"|1f 8b 08 00|"; depth:4; flowbits:set,et.exploitkitlanding; metadata: former_category INFO; classtype:trojan-activity; sid:2017910; rev:3; metadata:created_at 2013_12_30, updated_at 2013_12_30;)
` 

Name : **suspicious - gzipped file via JAVA - could be pack200-ed JAR** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-30

Last modified date : 2013-12-30

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017980
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO InformationCardSigninHelper ClassID (Vulnerable ActiveX Control in CVE-2013-3918)"; flow:established,to_client; file_data; content:"19916E01-B44E-4E31-94A4-4696DF46157B"; nocase; classtype:misc-activity; sid:2017980; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2014_01_16, updated_at 2016_07_01;)
` 

Name : **InformationCardSigninHelper ClassID (Vulnerable ActiveX Control in CVE-2013-3918)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-01-16

Last modified date : 2016-07-01

Rev version : 4

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018087
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Control Panel Applet File Download"; flow:established,to_client; flowbits:isset,ET.http.binary; content:"CPlApplet"; reference:url,msdn.microsoft.com/en-us/library/windows/desktop/bb776392%28v=vs.85%29.aspx; reference:url,www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf; classtype:policy-violation; sid:2018087; rev:2; metadata:created_at 2014_02_06, updated_at 2014_02_06;)
` 

Name : **Control Panel Applet File Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,msdn.microsoft.com/en-us/library/windows/desktop/bb776392%28v=vs.85%29.aspx|url,www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf

CVE reference : Not defined

Creation date : 2014-02-06

Last modified date : 2014-02-06

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018106
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Jar name JavaUpdate.jar"; flow:established,to_server; content:"/JavaUpdate.jar"; http_uri; nocase; content:"Java/1."; http_user_agent; metadata: former_category HUNTING; reference:url,www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf; classtype:bad-unknown; sid:2018106; rev:3; metadata:created_at 2014_02_10, updated_at 2014_02_10;)
` 

Name : **Suspicious Jar name JavaUpdate.jar** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf

CVE reference : Not defined

Creation date : 2014-02-10

Last modified date : 2014-02-10

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018220
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.ddns.info Domain"; flow:established,to_server; content:".ddns.info|0D 0A|"; nocase; http_header; classtype:bad-unknown; sid:2018220; rev:5; metadata:created_at 2011_12_14, updated_at 2011_12_14;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.ddns.info Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-14

Last modified date : 2011-12-14

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018221
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.ddns.name Domain"; flow:established,to_server; content:".ddns.name|0D 0A|"; nocase; http_header; classtype:bad-unknown; sid:2018221; rev:5; metadata:created_at 2011_12_14, updated_at 2011_12_14;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.ddns.name Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-14

Last modified date : 2011-12-14

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018233
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Sent Claiming To Be Image - Likely Exploit Kit"; flow:established,to_client; flowbits:isset,ET.http.javaclient; content:"Content-Type|3A| image/"; http_header; file_data; content:"PK"; within:2; content:".class"; fast_pattern; distance:10; within:500; metadata: former_category INFO; classtype:bad-unknown; sid:2018233; rev:2; metadata:created_at 2014_03_07, updated_at 2014_03_07;)
` 

Name : **JAR Sent Claiming To Be Image - Likely Exploit Kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-07

Last modified date : 2014-03-07

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018234
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Sent Claiming To Be Text Content - Likely Exploit Kit"; flow:established,to_client; flowbits:isset,ET.http.javaclient; content:"Content-Type|3A| text/"; http_header; file_data; content:"PK"; within:2; content:".class"; fast_pattern; distance:10; within:500; metadata: former_category INFO; classtype:bad-unknown; sid:2018234; rev:2; metadata:created_at 2014_03_07, updated_at 2014_03_07;)
` 

Name : **JAR Sent Claiming To Be Text Content - Likely Exploit Kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-07

Last modified date : 2014-03-07

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018334
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Phish - Saved Website Comment Observed"; flow:established,to_client; file_data; content:"<!-- saved from url=("; pcre:"/^\s*?\d+?\s*?\)https\x3a\x2f/Rsi"; content:"<form"; nocase; distance:0; metadata: former_category INFO; classtype:bad-unknown; sid:2018334; rev:2; metadata:created_at 2014_03_31, updated_at 2014_03_31;)
` 

Name : **Possible Phish - Saved Website Comment Observed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-31

Last modified date : 2014-03-31

Rev version : 2

Category : PHISHING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018396
`alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET INFO BrowseTor .onion Proxy Service SSL Cert"; flow:established,from_server; content:"|55 04 03|"; content:"|0f|*.browsetor.com"; nocase; distance:1; within:16; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2018396; rev:4; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2014_04_16, updated_at 2016_07_01;)
` 

Name : **BrowseTor .onion Proxy Service SSL Cert** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-04-16

Last modified date : 2016-07-01

Rev version : 4

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016806
`alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET INFO Tor2Web .onion Proxy Service SSL Cert (1)"; flow:established,from_server; content:"|55 04 03|"; content:"*.tor2web."; nocase; distance:2; within:10; metadata: former_category CURRENT_EVENTS; reference:url,uscyberlabs.com/blog/2013/04/30/tor-exploit-pak/; classtype:trojan-activity; sid:2016806; rev:5; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2013_05_01, updated_at 2016_07_01;)
` 

Name : **Tor2Web .onion Proxy Service SSL Cert (1)** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,uscyberlabs.com/blog/2013/04/30/tor-exploit-pak/

CVE reference : Not defined

Creation date : 2013-05-01

Last modified date : 2016-07-01

Rev version : 5

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015045
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Potential Common Malicious JavaScript Loop"; flow:established,to_client; content:"for("; content:"|3B|"; within:20; content:">=0|3B|"; fast_pattern; within:10; content:"--)"; within:10; pcre:"/for\x28[^\x3D\r\n]*[0-9]{1,6}\x2D[0-9]{1,5}\x3B[^\x3D\r\n]\x3E\x3D0\x3B[^\x29\r\n]\x2D\x2D\x29/"; classtype:bad-unknown; sid:2015045; rev:4; metadata:created_at 2012_07_06, updated_at 2012_07_06;)
` 

Name : **Potential Common Malicious JavaScript Loop** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-06

Last modified date : 2012-07-06

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018538
`alert tcp $EXTERNAL_NET [443,$HTTP_PORTS] -> $HOME_NET any (msg:"ET INFO tor2www .onion Proxy SSL cert"; flow:established,from_server; content:"|55 04 03|"; content:"*.tor2www."; nocase; distance:2; within:10; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2018538; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2014_06_06, updated_at 2016_07_01;)
` 

Name : **tor2www .onion Proxy SSL cert** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-06-06

Last modified date : 2016-07-01

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018904
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag false change port flag false)"; dsize:28; content:"|00 01 00 08|"; depth:4; content:"|00 03 00 04 00 00 00 00|"; fast_pattern; distance:16; within:8; threshold: type limit, track by_dst, count 1, seconds 120; reference:url,tools.ietf.org/html/rfc3489; classtype:protocol-command-decode; sid:2018904; rev:6; metadata:created_at 2014_08_06, updated_at 2014_08_06;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag false change port flag false)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/rfc3489

CVE reference : Not defined

Creation date : 2014-08-06

Last modified date : 2014-08-06

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018905
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag false change port flag true)"; dsize:28; content:"|00 01 00 08|"; depth:4; content:"|00 03 00 04 00 00 00 02|"; fast_pattern; distance:16; within:8; threshold: type limit, track by_dst, count 1, seconds 120; reference:url,tools.ietf.org/html/rfc3489; classtype:protocol-command-decode; sid:2018905; rev:6; metadata:created_at 2014_08_06, updated_at 2014_08_06;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag false change port flag true)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/rfc3489

CVE reference : Not defined

Creation date : 2014-08-06

Last modified date : 2014-08-06

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018906
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag true change port flag false)"; dsize:28; content:"|00 01 00 08|"; depth:4; content:"|00 03 00 04 00 00 00 04|"; fast_pattern; distance:16; within:8; threshold: type limit, track by_dst, count 1, seconds 120; reference:url,tools.ietf.org/html/rfc3489; classtype:protocol-command-decode; sid:2018906; rev:6; metadata:created_at 2014_08_06, updated_at 2014_08_06;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag true change port flag false)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/rfc3489

CVE reference : Not defined

Creation date : 2014-08-06

Last modified date : 2014-08-06

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018907
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag true change port flag true)"; dsize:28; content:"|00 01 00 08|"; depth:4; content:"|00 03 00 04 00 00 00 06|"; fast_pattern; distance:16; within:8; threshold: type limit, track by_dst, count 1, seconds 120; reference:url,tools.ietf.org/html/rfc3489; classtype:protocol-command-decode; sid:2018907; rev:5; metadata:created_at 2014_08_06, updated_at 2014_08_06;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Request obsolete rfc 3489 CHANGE-REQUEST attribute change IP flag true change port flag true)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/rfc3489

CVE reference : Not defined

Creation date : 2014-08-06

Last modified date : 2014-08-06

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013412
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.co.com.au domain"; flow:to_server,established; content:".co.com.au|0D 0A|"; http_header; classtype:bad-unknown; sid:2013412; rev:3; metadata:created_at 2011_08_16, updated_at 2011_08_16;)
` 

Name : **HTTP Request to a *.co.com.au domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-16

Last modified date : 2011-08-16

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013415
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.cz.tf domain"; flow:to_server,established; content:".cz.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013415; rev:3; metadata:created_at 2011_08_16, updated_at 2011_08_16;)
` 

Name : **HTTP Request to a *.cz.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-16

Last modified date : 2011-08-16

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013460
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.c0m.li domain"; flow:to_server,established; content:".c0m.li|0d 0a|"; http_header; classtype:bad-unknown; sid:2013460; rev:3; metadata:created_at 2011_08_25, updated_at 2011_08_25;)
` 

Name : **HTTP Request to a *.c0m.li domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-25

Last modified date : 2011-08-25

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013829
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.int.tf domain"; flow:to_server,established; content:".int.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013829; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.int.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013830
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.edu.tf domain"; flow:to_server,established; content:".edu.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013830; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.edu.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013831
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.us.tf domain"; flow:to_server,established; content:".us.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013831; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.us.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013832
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.ca.tf domain"; flow:to_server,established; content:".ca.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013832; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.ca.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013833
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.bg.tf domain"; flow:to_server,established; content:".bg.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013833; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.bg.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013834
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.ru.tf domain"; flow:to_server,established; content:".ru.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013834; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.ru.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013835
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.pl.tf domain"; flow:to_server,established; content:".pl.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013835; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.pl.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013837
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.de.tf domain"; flow:to_server,established; content:".de.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013837; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.de.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013838
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.at.tf domain"; flow:to_server,established; content:".at.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013838; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.at.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013839
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.ch.tf domain"; flow:to_server,established; content:".ch.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013839; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.ch.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013840
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.sg.tf domain"; flow:to_server,established; content:".sg.tf|0D 0A|"; http_header; classtype:bad-unknown; sid:2013840; rev:6; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.sg.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013841
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.nl.ai domain"; flow:to_server,established; content:".nl.ai|0D 0A|"; http_header; classtype:bad-unknown; sid:2013841; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.nl.ai domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013842
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.xe.cx domain"; flow:to_server,established; content:".xe.cx|0D 0A|"; http_header; classtype:bad-unknown; sid:2013842; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.xe.cx domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013844
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.orge.pl Domain"; flow:established,to_server; content:".orge.pl|0d 0a|"; http_header; nocase; classtype:bad-unknown; sid:2013844; rev:4; metadata:created_at 2011_11_04, updated_at 2011_11_04;)
` 

Name : **HTTP Request to a *.orge.pl Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2011-11-04

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014289
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a 3322.org.cn Domain"; flow:to_server,established; content:"Host|3a| "; http_header; content:".3322.org.cn|0D 0A|"; within:50; http_header; classtype:bad-unknown; sid:2014289; rev:3; metadata:created_at 2012_02_28, updated_at 2012_02_28;)
` 

Name : **HTTP Request to a 3322.org.cn Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-02-28

Last modified date : 2012-02-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014508
`alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET INFO DNS Query to a *.slyip.net Dynamic DNS Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:4; content:"|05|slyip|03|net|00|"; fast_pattern; nocase; distance:0; classtype:bad-unknown; sid:2014508; rev:5; metadata:created_at 2012_04_05, updated_at 2019_08_30;)
` 

Name : **DNS Query to a *.slyip.net Dynamic DNS Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-08-30

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014645
`#alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET INFO RuggedCom Banner with MAC"; flow:to_client,established; content:"Rugged Operating System"; content:"Copyright |28|c|29| RuggedCom"; distance:0; content:"MAC Address|3A|"; distance:0; flowbits:set,ET.RUGGED.BANNER; metadata: former_category INFO; reference:url,www.exploit-db.com/exploits/18779/; reference:url,arstechnica.com/business/news/2012/04/backdoor-in-mission-critical-hardware-threatens-power-traffic-control-systems.ars; classtype:attempted-admin; sid:2014645; rev:3; metadata:created_at 2012_04_27, updated_at 2012_04_27;)
` 

Name : **RuggedCom Banner with MAC** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.exploit-db.com/exploits/18779/|url,arstechnica.com/business/news/2012/04/backdoor-in-mission-critical-hardware-threatens-power-traffic-control-systems.ars

CVE reference : Not defined

Creation date : 2012-04-27

Last modified date : 2012-04-27

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015529
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Googlebot User-Agent Outbound (likely malicious)"; flow:to_server,established; content:"Googlebot"; nocase; http_header; pcre:"/^User-Agent\x3a[^\r\n]*?Googlebot/Hmi"; classtype:bad-unknown; sid:2015529; rev:4; metadata:created_at 2012_07_26, updated_at 2012_07_26;)
` 

Name : **Googlebot User-Agent Outbound (likely malicious)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-26

Last modified date : 2012-07-26

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013703
`alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET INFO Suspicious Self Signed SSL Certificate to 'My Company Ltd'"; flow:established,from_server; content:"|16 03|"; content:"|0b|"; within:7; content:"My Company Ltd"; classtype:bad-unknown; sid:2013703; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2011_09_27, updated_at 2016_07_01;)
` 

Name : **Suspicious Self Signed SSL Certificate to 'My Company Ltd'** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-27

Last modified date : 2016-07-01

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015743
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Revoked Adobe Code Signing Certificate Seen"; flow:established,to_client; content:"|30 82|"; content:"|a0 03 02 01 02 02 10 15 e5 ac 0a 48 70 63 71 8e 39 da 52 30 1a 04 88 30 0d 06 09 2a 86 48 86 f7 0d 01 01 05 05 00|"; distance:6; within:38; content:"|1e 17 0d|101215000000Z|17 0d|121214235959Z0"; distance:184; within:32; content:"Adobe Systems Incorporated"; distance:66; within:26; reference:url,www.adobe.com/support/security/advisories/apsa12-01.html; classtype:policy-violation; sid:2015743; rev:2; metadata:created_at 2012_09_28, updated_at 2012_09_28;)
` 

Name : **Revoked Adobe Code Signing Certificate Seen** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.adobe.com/support/security/advisories/apsa12-01.html

CVE reference : Not defined

Creation date : 2012-09-28

Last modified date : 2012-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019338
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Generic CollectGarbage in Hex"; flow:established,from_server; file_data; content:"|5c|x43|5c|x6f|5c|x6c|5c|x6c|5c|x65|5c|x63|5c|x74|5c|x47|5c|x61|5c|x72|5c|x62|5c|x61|5c|x67|5c|x65"; nocase; metadata: former_category HUNTING; classtype:suspicious-filename-detect; sid:2019338; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Informational, created_at 2014_10_02, updated_at 2016_07_01;)
` 

Name : **Generic CollectGarbage in Hex** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : suspicious-filename-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-02

Last modified date : 2016-07-01

Rev version : 6

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019821
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO WinHttpRequest (flowbits no alert)"; flow:established,to_server; content:"WinHttp.WinHttpRequest"; http_user_agent; fast_pattern; content:!".microsoft.com|0d 0a|"; http_header; content:!".qq.com|0d 0a|"; http_header; flowbits:set,et.WinHttpRequest; flowbits:noalert; classtype:trojan-activity; sid:2019821; rev:8; metadata:created_at 2014_12_01, updated_at 2014_12_01;)
` 

Name : **WinHttpRequest (flowbits no alert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-01

Last modified date : 2014-12-01

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019834
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Microsoft Compact Office Document Format File Download"; flow:established,from_server; file_data; content:"|D0 CF 11 E0 A1 B1 1A E1|"; within:8; flowbits:set,et.MCOFF; flowbits:noalert; classtype:misc-activity; sid:2019834; rev:2; metadata:created_at 2014_12_01, updated_at 2014_12_01;)
` 

Name : **Microsoft Compact Office Document Format File Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-01

Last modified date : 2014-12-01

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014925
`alert tcp $EXTERNAL_NET any -> $HOME_NET $SSH_PORTS (msg:"ET INFO NetSSH SSH Version String Hardcoded in Metasploit"; flow:established,to_server; content:"SSH-2.0-OpenSSH_5.0|0d 0a|"; depth:21; reference:url,github.com/rapid7/metasploit-framework/blob/master/lib/net/ssh/transport/server_version.rb; classtype:attempted-user; sid:2014925; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_06_19, updated_at 2016_07_01;)
` 

Name : **NetSSH SSH Version String Hardcoded in Metasploit** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : attempted-user

URL reference : url,github.com/rapid7/metasploit-framework/blob/master/lib/net/ssh/transport/server_version.rb

CVE reference : Not defined

Creation date : 2012-06-19

Last modified date : 2016-07-01

Rev version : 2

Category : INFO

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016149
`alert udp $HOME_NET any -> $EXTERNAL_NET 3478 (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"; content:"|00 01|"; depth:2; content:"|21 12 a4 42|"; distance:2; within:4; reference:url,tools.ietf.org/html/rfc5389; classtype:attempted-user; sid:2016149; rev:2; metadata:created_at 2013_01_04, updated_at 2013_01_04;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Request)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,tools.ietf.org/html/rfc5389

CVE reference : Not defined

Creation date : 2013-01-04

Last modified date : 2013-01-04

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016150
`alert udp $EXTERNAL_NET 3478 -> $HOME_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Response)"; content:"|01 01|"; depth:2; content:"|21 12 a4 42|"; distance:2; within:4; reference:url,tools.ietf.org/html/rfc5389; classtype:attempted-user; sid:2016150; rev:2; metadata:created_at 2013_01_04, updated_at 2013_01_04;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Response)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,tools.ietf.org/html/rfc5389

CVE reference : Not defined

Creation date : 2013-01-04

Last modified date : 2013-01-04

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018908
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Response)"; content:"|01 01 00 44|"; depth:4; content:"|00 01 00 08|"; distance:16; within:4; threshold:type limit, track by_src, count 1, seconds 60; reference:url,tools.ietf.org/html/rfc5389; classtype:protocol-command-decode; sid:2018908; rev:2; metadata:created_at 2014_08_07, updated_at 2014_08_07;)
` 

Name : **Session Traversal Utilities for NAT (STUN Binding Response)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/rfc5389

CVE reference : Not defined

Creation date : 2014-08-07

Last modified date : 2014-08-07

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015744
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE IsDebuggerPresent (Used in Malware Anti-Debugging)"; flow:established,to_client; flowbits:isset,ET.http.binary; content:!"|0d 0a|x-avast"; http_header; file_data; content:"IsDebuggerPresent"; classtype:misc-activity; sid:2015744; rev:4; metadata:created_at 2012_09_28, updated_at 2012_09_28;)
` 

Name : **EXE IsDebuggerPresent (Used in Malware Anti-Debugging)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-28

Last modified date : 2012-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021076
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Dotted Quad Host MZ Response"; flow:established,to_client; flowbits:isset,http.dottedquadhost; file_data; content:"MZ"; within:2; content:"PE|00 00|"; distance:0; metadata: former_category INFO; classtype:bad-unknown; sid:2021076; rev:2; metadata:created_at 2015_05_07, updated_at 2015_05_07;)
` 

Name : **SUSPICIOUS Dotted Quad Host MZ Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2015-05-07

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021216
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Executable Downloaded from Google Cloud Storage"; flow:established,to_client; content:"x-goog-generation|3a 20|"; http_header; fast_pattern; content:"x-goog-metageneration|3a 20|"; http_header; content:"x-goog-stored-content-encoding|3a 20|"; http_header; content:"x-goog-stored-content-length|3a 20|"; http_header; content:"x-goog-hash|3a 20|"; http_header; file_data; content:"MZ"; within:2; reference:md5,e742e844d0ea55ef9f1c68491c702120; classtype:trojan-activity; sid:2021216; rev:3; metadata:created_at 2015_06_08, updated_at 2015_06_08;)
` 

Name : **Executable Downloaded from Google Cloud Storage** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,e742e844d0ea55ef9f1c68491c702120

CVE reference : Not defined

Creation date : 2015-06-08

Last modified date : 2015-06-08

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021311
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO User-Agent (wininet)"; flow:established,to_server; content:"User-Agent|3a 20|wininet|0d 0a|"; http_header; flowbits:set,ET.wininet.UA; flowbits:noalert; classtype:misc-activity; sid:2021311; rev:3; metadata:created_at 2015_06_19, updated_at 2015_06_19;)
` 

Name : **User-Agent (wininet)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-06-19

Last modified date : 2015-06-19

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017321
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS IRC - NICK and Possible Windows XP/7"; flow:established,to_server; content:"NICK "; depth:5; pcre:"/^[^\r\n]*(?:W(?:in(?:dows)?)?[^a-z0-9]?(XP|[7-8])|Vista)/Ri"; content:!"|20|XP/7"; metadata: former_category INFO; classtype:bad-unknown; sid:2017321; rev:8; metadata:created_at 2013_08_13, updated_at 2013_08_13;)
` 

Name : **SUSPICIOUS IRC - NICK and Possible Windows XP/7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-13

Last modified date : 2013-08-13

Rev version : 8

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022055
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PK/Compressed doc/JAR header"; flow:from_server,established; file_data; content:"|50 4B 03 04|"; depth:4; flowbits:set,ET.zipfile; flowbits:noalert; classtype:misc-activity; sid:2022055; rev:2; metadata:created_at 2015_11_10, updated_at 2015_11_10;)
` 

Name : **PK/Compressed doc/JAR header** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-10

Last modified date : 2015-11-10

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022220
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO possible .jpg download by VBA macro"; flow:established,to_server; content:"GET"; http_method; content:".jpg"; http_uri; content:!"Referer|3A|"; http_header; content:!"Accept-Language|3A|"; http_header; content:"Accept|3a|"; http_header; content:"Accept|3a 20|*/*|0d 0a|Accept-Encoding|3a 20|gzip, deflate|0d 0a|User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 7.0|3b| Windows NT"; depth:102; fast_pattern:82,20; http_header; pcre:"/\.jpg(?:\?\d+)?$/U"; flowbits:set,ET.vba-jpg-dl; flowbits:noalert; classtype:trojan-activity; sid:2022220; rev:2; metadata:created_at 2015_12_04, updated_at 2015_12_04;)
` 

Name : **possible .jpg download by VBA macro** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-04

Last modified date : 2015-12-04

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022262
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO possible .jpg download by VBA macro"; flow:established,to_server; content:"GET"; http_method; content:".jpg"; http_uri; content:!"Referer|3A|"; http_header; content:"Accept|3a 20|*/*|0d 0a|Accept-Language|3a 20|en-us|0d 0a|Range|3a 20|"; http_header; content:"MSIE 7.0|3b| Windows NT"; fast_pattern; http_header; flowbits:set,ET.vba-jpg-dl; flowbits:noalert; classtype:trojan-activity; sid:2022262; rev:3; metadata:created_at 2015_12_14, updated_at 2015_12_14;)
` 

Name : **possible .jpg download by VBA macro** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-14

Last modified date : 2015-12-14

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022285
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO ZoneAlarm Download Flowbit Set"; flow:established,to_server; content:"pkg"; http_uri; content:"Host|3a 20|"; http_header; nocase; content:"zonealarm.com|0d 0a|"; distance:0; http_header; pcre:"/^Host\x3a[^\r\n]+?zonealarm\.com\r?$/Hmi"; flowbits:set,ET.ZoneAlarm.Site.Download; flowbits:noalert; classtype:misc-activity; sid:2022285; rev:2; metadata:created_at 2015_12_18, updated_at 2015_12_18;)
` 

Name : **ZoneAlarm Download Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-18

Last modified date : 2015-12-18

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003287
`#alert udp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 UDP Proxy Inbound Connect Request (Linux Source)"; content:"|00 00|"; depth:2; content:"|01|"; offset:3; depth:1; threshold:type both, track by_dst, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003287; classtype:protocol-command-decode; sid:2003287; rev:7; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 UDP Proxy Inbound Connect Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003287

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003286
`#alert udp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 UDP Proxy Inbound Connect Request (Windows Source)"; content:"|00 00|"; depth:2; content:"|01|"; offset:3; depth:1; threshold:type both, track by_dst, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003286; classtype:protocol-command-decode; sid:2003286; rev:8; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 UDP Proxy Inbound Connect Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003286

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015898
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 1 User-Agent"; flow: established,to_server; content:"Windows NT 1"; nocase; http_user_agent; content:!"0"; within:1; http_user_agent; pcre:"/^[^0-9]/VR"; classtype:trojan-activity; sid:2015898; rev:4; metadata:created_at 2012_11_19, updated_at 2012_11_19;)
` 

Name : **Suspicious Windows NT version 1 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-19

Last modified date : 2012-11-19

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022729
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO PhishMe.com Phishing Exercise - Client Plugins"; flow:to_server,established; urilen:15; content:"POST"; http_method; content:"/plugin_surveys"; http_uri; fast_pattern; content:"_phishme.com_session_id="; http_cookie; metadata: former_category INFO; classtype:trojan-activity; sid:2022729; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2016_04_13, updated_at 2016_07_01;)
` 

Name : **PhishMe.com Phishing Exercise - Client Plugins** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods. A whitepaper concerning modern phishing obfuscation methods can be found at https://www.proofpoint.com/us/threat-insight/post/Obfuscation-Techniques-In-Phishing-Attacks

Tags : Phishing

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-04-13

Last modified date : 2016-07-01

Rev version : 2

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022915
`alert udp any 67 -> any 68 (msg:"ET INFO Web Proxy Auto Discovery Protocol WPAD DHCP 252 option Possible BadTunnel"; content:"|02|"; depth:1; content:"|fc|"; byte_jump:1,0,relative,post_offset -9; content:"/wpad.dat"; within:9; fast_pattern; classtype:protocol-command-decode; sid:2022915; rev:1; metadata:created_at 2016_06_24, updated_at 2016_06_24;)
` 

Name : **Web Proxy Auto Discovery Protocol WPAD DHCP 252 option Possible BadTunnel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-06-24

Last modified date : 2016-06-24

Rev version : 1

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022965
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Excel Add-in Download M1"; flow:to_server,established; content:".xla"; nocase; http_uri; pcre:"/\.xla$/Ui"; metadata: former_category INFO; reference:url,blogs.mcafee.com/mcafee-labs/patch-now-simple-office-protected-view-bypass-could-have-big-impact/; classtype:bad-unknown; sid:2022965; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2016_07_13, performance_impact Low, updated_at 2016_07_13;)
` 

Name : **SUSPICIOUS Excel Add-in Download M1** 

Attack target : Client_Endpoint

Description : This signature will fire for Excel add-in download file extensions which may or may not be related to CVE-2016-3279.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,blogs.mcafee.com/mcafee-labs/patch-now-simple-office-protected-view-bypass-could-have-big-impact/

CVE reference : Not defined

Creation date : 2016-07-13

Last modified date : 2016-07-13

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2022966
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Excel Add-in Download M2"; flow:to_server,established; content:".xla"; nocase; http_header; pcre:"/Content-Disposition\x3a[^\r\n]*?\.xla[\s\x22\x27]/Hi"; metadata: former_category INFO; reference:url,blogs.mcafee.com/mcafee-labs/patch-now-simple-office-protected-view-bypass-could-have-big-impact/; classtype:bad-unknown; sid:2022966; rev:2; metadata:created_at 2016_07_13, updated_at 2016_07_13;)
` 

Name : **SUSPICIOUS Excel Add-in Download M2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.mcafee.com/mcafee-labs/patch-now-simple-office-protected-view-bypass-could-have-big-impact/

CVE reference : Not defined

Creation date : 2016-07-13

Last modified date : 2016-07-13

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022996
`#alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO QUIC UDP Internet Connections Protocol Client Hello (OUTBOUND)"; flow:to_server; content:"|80 01|CHLO"; content:"PAD"; content:"SNI"; content:"CCS"; content:"PDMD"; content:"VERS"; nocase;flowbits:set,ET.QUIC.FirstClientHello; reference:url,tools.ietf.org/html/draft-tsvwg-quic-protocol-00; classtype:protocol-command-decode; sid:2022996; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2016_08_01, performance_impact Low, updated_at 2016_08_01;)
` 

Name : **QUIC UDP Internet Connections Protocol Client Hello (OUTBOUND)** 

Attack target : Client_Endpoint

Description : This signature detects the Client Hello when a QUIC client connects to a server. The client sends an inchoate (empty) client hello (CHLO), the server sends a rejection (REJ) with the information the client needs to make forward progress.

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/draft-tsvwg-quic-protocol-00

CVE reference : Not defined

Creation date : 2016-08-01

Last modified date : 2016-08-01

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023067
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Symantec Download Flowbit Set"; flow:established,to_server; content:".symantec.com|0d 0a|"; http_header; nocase; pcre:"/^Host\x3a[^\r\n]*\.symantec\.com(?:\x3a\d{1,5})?\r?$/Hmi";  flowbits:set,ET.Symantec.Site.Download; flowbits:noalert; classtype:misc-activity; sid:2023067; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2016_08_16, performance_impact Low, updated_at 2016_08_16;)
` 

Name : **Symantec Download Flowbit Set** 

Attack target : Client_Endpoint

Description : This sig is setting a flowbits to avoid False Positives with Symantec Products in sid 2008438.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-08-16

Last modified date : 2016-08-16

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2018302
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Phish - Mirrored Website Comment Observed"; flow:established,to_client; file_data; content:"<!-- Mirrored from "; content:"by HTTrack Website Copier/"; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2018302; rev:5; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2014_03_21, performance_impact Low, updated_at 2016_08_24;)
` 

Name : **Possible Phish - Mirrored Website Comment Observed** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-21

Last modified date : 2016-08-24

Rev version : 5

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023139
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Form Data Submitted to yolasite.com - Possible Phishing"; flow:to_server,established; content:"POST"; http_method; content:"/formservice/"; http_uri; depth:13; content:"forms.yola.com"; http_header; fast_pattern; metadata: former_category INFO; classtype:trojan-activity; sid:2023139; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2016_08_26, performance_impact Low, updated_at 2016_08_26;)
` 

Name : **Form Data Submitted to yolasite.com - Possible Phishing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-08-26

Last modified date : 2016-08-26

Rev version : 2

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025659
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Dropbox Page - Possible Phishing Landing"; flow:to_client,established; content:"200"; http_stat_code; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<title>Dropbox"; fast_pattern; content:"<form"; distance:0; nocase; content:"password"; nocase; distance:0; content:!"_csp_external_script_nonce"; content:!"when_ready_configure_requirejs"; distance:0; content:!"DETERMINISTIC_MONKEY_CHECK"; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2025659; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2016_08_29, performance_impact Low, updated_at 2018_07_12;)
` 

Name : **Suspicious Dropbox Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-08-29

Last modified date : 2018-07-12

Rev version : 3

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025669
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Google Docs Page - Possible Phishing Landing"; flow:to_client,established; content:"200"; http_stat_code; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<title>"; content:"Google Docs"; fast_pattern; within:20; content:"<form"; distance:0; nocase; content:"password"; nocase; distance:0; content:!"<title>|0a 20 20 20 20 20 20|Google Docs"; metadata: former_category INFO; classtype:trojan-activity; sid:2025669; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2016_08_29, performance_impact Low, updated_at 2018_07_12;)
` 

Name : **Suspicious Google Docs Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-08-29

Last modified date : 2018-07-12

Rev version : 3

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023464
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD"; flow:established,to_client; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:isset,ET.SuspExeTLDs; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023464; rev:2; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2017_10_12;)
` 

Name : **Possible EXE Download From Suspicious TLD** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2017-10-12

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023640
`alert tcp $EXTERNAL_NET any -> $HOME_NET 33434 (msg:"ET INFO Noction IRP Probe"; flow:stateless; flags:SP; content:"|4E 4F 43 54 49 4F 4E 20 49 52 50|"; reference:url,www.noction.com/faq; classtype:bad-unknown; sid:2023640; rev:1; metadata:deployment Perimeter, signature_severity Minor, created_at 2016_12_14, performance_impact Low, updated_at 2016_12_14;)
` 

Name : **Noction IRP Probe** 

Attack target : Not defined

Description : This signatures matches Noction Intelligent Routing Platform (IRP) which actively probes remote destination networks for metrics like latency, packet loss, throughput.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.noction.com/faq

CVE reference : Not defined

Creation date : 2016-12-14

Last modified date : 2016-12-14

Rev version : 1

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023668
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Unconfigured nginx Access"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"|3C|title|3E|Welcome to nginx|213C2F|title|3E|"; classtype:bad-unknown; sid:2023668; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2016_12_19, performance_impact Low, updated_at 2016_12_19;)
` 

Name : **Unconfigured nginx Access** 

Attack target : Client_Endpoint

Description : Alert is generated when client visits unconfigured nginx page.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-12-19

Last modified date : 2016-12-19

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2014519
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE - Served Inline HTTP"; flow:to_client,established; content:"Content-Disposition"; nocase; http_header; content:"inline"; nocase; http_header; file_data; content:"MZ"; depth:2; fast_pattern; classtype:misc-activity; sid:2014519; rev:7; metadata:created_at 2012_04_05, updated_at 2012_04_05;)
` 

Name : **EXE - Served Inline HTTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2012-04-05

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023714
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO ATF file in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"|41 54 46|"; within:3; flowbits:set,ET.atf.in.http; flowbits:noalert; classtype:not-suspicious; sid:2023714; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, created_at 2017_01_10, updated_at 2017_01_10;)
` 

Name : **ATF file in HTTP Flowbit Set** 

Attack target : Client_Endpoint

Description : This signature matches at a Adobe Photoshop Transfer Function file magic bytes download in HTTP.

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-01-10

Last modified date : 2017-01-10

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023715
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Adobe FDF in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"%FDF-"; within:5; flowbits:set,ET.fdf.in.http; flowbits:noalert; classtype:not-suspicious; sid:2023715; rev:2; metadata:affected_product Adobe_Reader, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_01_10, performance_impact Low, updated_at 2017_01_10;)
` 

Name : **Adobe FDF in HTTP Flowbit Set** 

Attack target : Client_Endpoint

Description : This signature matches on the magic bytes of Acrobat Forms Data Format file.

Tags : Not defined

Affected products : Adobe_Reader

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-01-10

Last modified date : 2017-01-10

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2013267
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Hex Obfuscated JavaScript Heap Spray 0a0a0a0a"; flow:established,to_client; file_data; content:"|5C|x0a|5C|x0a|5C|x0a|5C|x0a"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013267; rev:5; metadata:created_at 2011_07_14, updated_at 2017_01_27;)
` 

Name : **Possible Hex Obfuscated JavaScript Heap Spray 0a0a0a0a** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2017-01-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023818
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Windows Update/Microsoft FP Flowbit"; flow:established,to_server; content:".windowsupdate.com|0d 0a|"; http_header; pcre:"/\.windowsupdate\.com\r?$/Hmi"; flowbits:set,ET.INFO.WindowsUpdate; flowbits:noalert; classtype:trojan-activity; sid:2023818; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_01, performance_impact Low, updated_at 2017_02_01;)
` 

Name : **Windows Update/Microsoft FP Flowbit** 

Attack target : Client_Endpoint

Description : This signature sets a flowbits to another signature not generate False Positives.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-02-01

Last modified date : 2017-02-01

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023713
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO MP4 in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"|66 74 79 70 6D|"; offset:4; depth:5; content:"mp4"; within:12; flowbits:set,ET.mp4.in.http; flowbits:noalert; classtype:not-suspicious; sid:2023713; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_01_10, performance_impact Low, updated_at 2017_02_10;)
` 

Name : **MP4 in HTTP Flowbit Set** 

Attack target : Client_Endpoint

Description : This signatures matches on the magic bytes of an mp4 file download in HTTP. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-01-10

Last modified date : 2017-02-10

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023892
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO MP4 in HTTP Flowbit Set M2"; flow:from_server,established; file_data; content:"|66 74 79 70 69 73 6f 6d|"; offset:4; depth:8; flowbits:set,ET.mp4.in.http; flowbits:noalert; classtype:not-suspicious; sid:2023892; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_10, performance_impact Low, updated_at 2017_02_10;)
` 

Name : **MP4 in HTTP Flowbit Set M2** 

Attack target : Client_Endpoint

Description : This signatures matches on the magic bytes of an mp4 file download in HTTP.

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-02-10

Last modified date : 2017-02-10

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023900
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO MP4 in HTTP Flowbit Set M3"; flow:from_server,established; file_data; content:"|66 74 79 70 71 74 20 20|"; offset:4; depth:8; flowbits:set,ET.mp4.in.http; flowbits:noalert; classtype:not-suspicious; sid:2023900; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_14, performance_impact Low, updated_at 2017_02_14;)
` 

Name : **MP4 in HTTP Flowbit Set M3** 

Attack target : Client_Endpoint

Description : This signatures matches on the magic bytes of an mp4 file download in HTTP.

Tags : Not defined

Affected products : Any

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-02-14

Last modified date : 2017-02-14

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2024006
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Opera Adblocker Update Flowbit Set"; flow:established,to_server; content:"Host|3a 20|get.geo.opera.com.global.prod.fastly.net|0d 0a|"; http_header; flowbits:set,ET.opera.adblock; flowbits:noalert; classtype:not-suspicious; sid:2024006; rev:2; metadata:deployment Perimeter, signature_severity Informational, created_at 2017_02_22, performance_impact Low, updated_at 2017_02_22;)
` 

Name : **Opera Adblocker Update Flowbit Set** 

Attack target : Not defined

Description : Sets flowbit for opera adblocker update, which contains malicious uri patterns

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-02-22

Last modified date : 2017-02-22

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2024029
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5500 (msg:"ET INFO Suspicious VNC Remote Admin Request"; flow:to_server,established; content:"|49 44 3a|"; depth:3; content:"temp"; nocase; fast_pattern; distance:0; content:"|52 46 42 20 30 30 33 2e 30 30 38 0a|"; distance:0; metadata: former_category INFO; reference:md5,2faf3040e8286d506144a0585d8f4162; classtype:trojan-activity; sid:2024029; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_03_01, performance_impact Low, updated_at 2017_03_01;)
` 

Name : **Suspicious VNC Remote Admin Request** 

Attack target : Client_Endpoint

Description : Alerts on VNC communications originating from temp directory. Observed in remote admin malware used by the gamaredon group.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,2faf3040e8286d506144a0585d8f4162

CVE reference : Not defined

Creation date : 2017-03-01

Last modified date : 2017-03-01

Rev version : 1

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023997
`#alert tcp any any -> any [139,445] (msg:"ET INFO Potentially unsafe SMBv1 protocol in use"; flow:established,to_server; content:"|FF|SMB"; offset:4; depth:4; content:!"r"; within:1; threshold: type limit, count 1, track by_src, seconds 1200; metadata: former_category INFO; reference:url,www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices; reference:url,blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/; classtype:not-suspicious; sid:2023997; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_17, performance_impact Low, updated_at 2017_03_03;)
` 

Name : **Potentially unsafe SMBv1 protocol in use** 

Attack target : Client_Endpoint

Description : Alerts on SMB version 1 which has been deemed unsafe and insecure by Microsoft.


Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : not-suspicious

URL reference : url,www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices|url,blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/

CVE reference : Not defined

Creation date : 2017-02-17

Last modified date : 2017-03-03

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2022380
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dns-free.ru Domain"; flow:to_server,established; content:".dns-free.com|0D 0A|"; http_header; classtype:bad-unknown; sid:2022380; rev:3; metadata:created_at 2016_01_19, updated_at 2016_01_19;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dns-free.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2016-01-19

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022379
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dyn-dns.ru Domain"; flow:to_server,established; content:".dyn-dns.ru|0D 0A|"; http_header; classtype:bad-unknown; sid:2022379; rev:3; metadata:created_at 2016_01_19, updated_at 2016_01_19;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dyn-dns.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2016-01-19

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022378
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dnsip.ru Domain"; flow:to_server,established; content:".dnsip.ru|0D 0A|"; http_header; metadata: former_category INFO; classtype:bad-unknown; sid:2022378; rev:2; metadata:created_at 2016_01_19, updated_at 2017_03_08;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dnsip.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2017-03-08

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022377
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dnsalias.ru Domain"; flow:to_server,established; content:".dnsalias.ru|0D 0A|"; http_header; metadata: former_category INFO; classtype:bad-unknown; sid:2022377; rev:3; metadata:created_at 2016_01_19, updated_at 2017_03_08;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dnsalias.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2017-03-08

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016693
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS UA starting with Mozilla/8"; flow:established,to_server; content:"Mozilla/8"; nocase; depth:9; http_user_agent; classtype:bad-unknown; sid:2016693; rev:5; metadata:created_at 2013_04_01, updated_at 2013_04_01;)
` 

Name : **SUSPICIOUS UA starting with Mozilla/8** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2013-04-01

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010908
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake"; flow:to_server,established; content:"User-Agent|3a| Mozilla/5.0|0d 0a|"; nocase; http_header; content:!"autodesk.com"; http_header; metadata: former_category MALWARE; reference:url,doc.emergingthreats.net/2010908; classtype:trojan-activity; sid:2010908; rev:7; metadata:created_at 2010_07_30, updated_at 2017_04_03;)
` 

Name : **Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2010908

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-04-03

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012118
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INFO http string in hex Possible Obfuscated Exploit Redirect"; flow:established,to_client; content:"=[|22 5c|x68|5c|x74|5c|x74|5c|x70|5c|x3A|5c|x2F|5c|x2F|5c|"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2012118; rev:3; metadata:created_at 2010_12_30, updated_at 2017_04_14;)
` 

Name : **http string in hex Possible Obfuscated Exploit Redirect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-12-30

Last modified date : 2017-04-14

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013436
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Redirection to driveby Page Home index.php"; flow:established,from_server; content:"/Home/index.php|22| width=1 height=1 scrolling=no></iframe>"; metadata: former_category INFO; classtype:bad-unknown; sid:2013436; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_08_19, updated_at 2017_04_14;)
` 

Name : **Redirection to driveby Page Home index.php** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-19

Last modified date : 2017-04-14

Rev version : 4

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024240
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO ARM File Requested via WGET (set)"; flow:to_server,established; content:"GET"; http_method; content:"Wget/"; depth:5; http_user_agent; fast_pattern; pcre:"/\.(?:arm(?:5n|7)?|m(?:ips|psl))$/U"; flowbits:set,ET.armwget; flowbits:noalert; metadata: former_category INFO; classtype:policy-violation; sid:2024240; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2017_04_25, updated_at 2017_04_25;)
` 

Name : **ARM File Requested via WGET (set)** 

Attack target : Client_Endpoint

Description : This signature detects HTTP requests for common ARM extensions in http_uri via wget. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-04-25

Last modified date : 2017-04-25

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024283
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Miniproxy Cloned Page - Possible Phishing Landing"; flow:from_server,established; content:"200"; http_stat_code; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<!-- Proxified page constructed by miniProxy"; fast_pattern:22,20; nocase; within:100; metadata: former_category INFO; reference:url,github.com/joshdick/miniProxy; classtype:trojan-activity; sid:2024283; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_05_09, updated_at 2017_05_09;)
` 

Name : **Miniproxy Cloned Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : url,github.com/joshdick/miniProxy

CVE reference : Not defined

Creation date : 2017-05-09

Last modified date : 2017-05-09

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024292
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Bitcoin QR Code Generated via Btcfrog.com"; flow:established,to_server; content:"/qr/bitcoinPNG.php?address="; fast_pattern; http_uri; content:"Host|3a 20|www.btcfrog.com|0d 0a|"; http_header; metadata: former_category INFO; classtype:misc-activity; sid:2024292; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_05_12, performance_impact Low, updated_at 2017_05_12;)
` 

Name : **Bitcoin QR Code Generated via Btcfrog.com** 

Attack target : Client_Endpoint

Description : This signature detects Bitcoin QR Code Generated via Btcfrog.com.

Tags : Not defined

Affected products : Not defined

Alert Classtype : coin-mining

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-05-12

Last modified date : 2017-05-12

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025227
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Phishing Landing - Common Multiple JS Unescape May 25 2017"; flow:from_server,established; file_data; content:"<script type=|22|text/javascript|22|>|0d 0a|<!--|0d 0a|"; nocase; content:"document.write(unescape(|27|"; nocase; fast_pattern:5,20; within:25; content:"|27 29 29 3b 0d 0a|//-->|0d 0a|</script>"; nocase; distance:0; content:"<script type=|22|text/javascript|22|>|0d 0a|<!--|0d 0a|"; nocase; distance:0; content:"document.write(unescape(|27|"; nocase; within:25; content:"|27 29 29 3b 0d 0a|//-->|0d 0a|</script>"; nocase; distance:0; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2025227; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_05_25, updated_at 2018_01_22;)
` 

Name : **Possible Phishing Landing - Common Multiple JS Unescape May 25 2017** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-05-25

Last modified date : 2018-01-22

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024375
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible Successful Hostinger Generic Phish Jun 09 2017"; flow:to_server,established; content:"POST"; http_method; content:"wb_form_id="; nocase; depth:11; http_client_body; fast_pattern; content:"&message=&wb_input_0="; nocase; distance:8; within:21; http_client_body; content:"&wb_input_0="; nocase; http_client_body; distance:0; content:"&wb_input_1="; nocase; http_client_body; distance:0; content:"&wb_input_1="; nocase; http_client_body; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2024375; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2017_06_09, updated_at 2017_06_09;)
` 

Name : **Possible Successful Hostinger Generic Phish Jun 09 2017** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : credential-theft

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-06-09

Last modified date : 2017-06-09

Rev version : 2

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024432
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious HTML Hex Obfuscated Title - Possible Phishing Landing Jun 28 2017"; flow:from_server,established; content:"200"; http_stat_code; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<title>"; nocase; content:!"</title>"; nocase; within:20; content:"|26 23|x"; within:20; content:"|3b 26 23|x"; distance:2; within:4; fast_pattern; content:"|3b 26 23|x"; distance:2; within:4; content:"|3b 26 23|x"; distance:2; within:4; content:"|3b 26 23|x"; distance:2; within:4; content:"</title>"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2024432; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_06_28, updated_at 2017_06_28;)
` 

Name : **Suspicious HTML Hex Obfuscated Title - Possible Phishing Landing Jun 28 2017** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Not defined

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-06-28

Last modified date : 2017-06-28

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024505
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Phishery Phishing Tool - Default SSL Certificate Observed"; flow:established,from_server; content:"|55 04 03|"; content:"|08|go-phish"; fast_pattern; distance:1; within:9; metadata: former_category INFO; reference:url,github.com/ryhanson/phishery; classtype:trojan-activity; sid:2024505; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2017_07_28, updated_at 2017_07_28;)
` 

Name : **Phishery Phishing Tool - Default SSL Certificate Observed** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : url,github.com/ryhanson/phishery

CVE reference : Not defined

Creation date : 2017-07-28

Last modified date : 2017-07-28

Rev version : 1

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024763
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Adilbo HTML Encoder Observed"; flow:established,to_client; file_data; content:"|2f 2a 20 61 64 69 6c 62 6f 20 48 54 4d 4c 20 45 6e 63 6f 64 65 72|"; fast_pattern:2,20; content:"*|20 20|Checksum|3a 20|927c770095e0daa48298343b8fd14624"; within:200; metadata: former_category INFO; classtype:policy-violation; sid:2024763; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2017_09_23, updated_at 2017_09_23;)
` 

Name : **Adilbo HTML Encoder Observed** 

Attack target : Client_Endpoint

Description : This free to use HTML encoder is commonly observed being used in obscuring phishing and scam pages.

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-09-23

Last modified date : 2017-09-23

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024764
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Darkwave Popads Pop Under Redirect"; flow:established,to_client; file_data; content:"|2f 2a 20 50 72 69 76 65 74 20 64 61 72 6b 76 2e 20 45 61 63 68 20 64 6f 6d 61 69 6e 20 69 73 20 32 68 20 66 6f 78 20 64 65 61 64 20 2a 2f|"; metadata: former_category INFO; classtype:policy-violation; sid:2024764; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2017_09_23, updated_at 2017_09_23;)
` 

Name : **Suspicious Darkwave Popads Pop Under Redirect** 

Attack target : Client_Endpoint

Description : Suspicious pop under redirect

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-09-23

Last modified date : 2017-09-23

Rev version : 1

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024829
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Download of Embedded OpenType (EOT) File flowbit set"; flow:established,to_client; file_data; content:"|4c 50|"; offset:34; depth:2; flowbits:set,ET.EOT.Download; flowbits:noalert; metadata: former_category INFO; reference:url,www.w3.org/Submission/EOT/#FileFormat; classtype:misc-activity; sid:2024829; rev:2; metadata:affected_product Internet_Explorer, affected_product Mac_OSX, affected_product Microsoft_Edge_Browser, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2017_10_10, performance_impact Low, updated_at 2017_10_10;)
` 

Name : **Download of Embedded OpenType (EOT) File flowbit set** 

Attack target : Client_Endpoint

Description : Signature to detect Embedded Open Type Font download.

Tags : Not defined

Affected products : Internet_Explorer

Alert Classtype : misc-activity

URL reference : url,www.w3.org/Submission/EOT/#FileFormat

CVE reference : Not defined

Creation date : 2017-10-10

Last modified date : 2017-10-10

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2003281
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 5050 Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 13 ba|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category INFO; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003281; classtype:protocol-command-decode; sid:2003281; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 5050 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003281

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003268
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 443 Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 01 bb|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category INFO; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003268; classtype:protocol-command-decode; sid:2003268; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 443 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003268

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003269
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 443 Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 01 bb|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category INFO; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003269; classtype:protocol-command-decode; sid:2003269; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 443 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003269

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003256
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 25 Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 00 19|"; depth:4; threshold:type both, track by_src, count 2, seconds 900; metadata: former_category INFO; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003256; classtype:protocol-command-decode; sid:2003256; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 25 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003256

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003254
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 25 Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|00 19|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003254; classtype:protocol-command-decode; sid:2003254; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 25 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003254

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003255
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 25 Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|00 19|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003255; classtype:protocol-command-decode; sid:2003255; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 25 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003255

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003257
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 25 Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 00 19|"; depth:4; threshold:type both, track by_src, count 2, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003257; classtype:protocol-command-decode; sid:2003257; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 25 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003257

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003258
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 DNS Inbound Request (Windows Source)"; dsize:10<>40; flow:established,to_server; content:"|05 01 00 03|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003258; classtype:protocol-command-decode; sid:2003258; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 DNS Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003258

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003259
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 DNS Inbound Request (Linux Source)"; dsize:10<>40; flow:established,to_server; content:"|05 01 00 03|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003259; classtype:protocol-command-decode; sid:2003259; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 DNS Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003259

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003260
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 HTTP Proxy Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|00 50|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003260; classtype:protocol-command-decode; sid:2003260; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 HTTP Proxy Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003260

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003261
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 HTTP Proxy Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|00 50|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003261; classtype:protocol-command-decode; sid:2003261; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 HTTP Proxy Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003261

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003262
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 HTTP Proxy Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 00 50|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003262; classtype:protocol-command-decode; sid:2003262; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 HTTP Proxy Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003262

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003263
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 HTTP Proxy Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 00 50|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003263; classtype:protocol-command-decode; sid:2003263; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 HTTP Proxy Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003263

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003266
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 443 Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|01 bb|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003266; classtype:protocol-command-decode; sid:2003266; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 443 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003266

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003267
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 443 Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|01 bb|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003267; classtype:protocol-command-decode; sid:2003267; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 443 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003267

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003270
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 5190 Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|14 46|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003270; classtype:protocol-command-decode; sid:2003270; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 5190 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003270

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003271
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 5190 Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|14 46|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003271; classtype:protocol-command-decode; sid:2003271; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 5190 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003271

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003272
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 5190 Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 14 46|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003272; classtype:protocol-command-decode; sid:2003272; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 5190 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003272

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003273
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 5190 Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 14 46|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003273; classtype:protocol-command-decode; sid:2003273; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 5190 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003273

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003274
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 1863 Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|07 47|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003274; classtype:protocol-command-decode; sid:2003274; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 1863 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003274

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003275
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 1863 Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|07 47|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003275; classtype:protocol-command-decode; sid:2003275; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 1863 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003275

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003276
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 1863 Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 07 47|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003276; classtype:protocol-command-decode; sid:2003276; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 1863 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003276

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003277
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 1863 Inbound Request (Linux Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 07 47|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003277; classtype:protocol-command-decode; sid:2003277; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 1863 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003277

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003278
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 5050 Inbound Request (Windows Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|13 ba|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003278; classtype:protocol-command-decode; sid:2003278; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 5050 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003278

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003279
`alert tcp $EXTERNAL_NET 32768:61000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv5 Port 5050 Inbound Request (Linux Source)"; dsize:10; flow:established,to_server; content:"|05 01 00 01|"; depth:4; content:"|13 ba|"; offset:8; depth:2; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003279; classtype:protocol-command-decode; sid:2003279; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv5 Port 5050 Inbound Request (Linux Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003279

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003280
`alert tcp $EXTERNAL_NET 1024:5000 -> $HOME_NET 1024:65535 (msg:"ET INFO SOCKSv4 Port 5050 Inbound Request (Windows Source)"; dsize:9<>18; flow:established,to_server; content:"|04 01 13 ba|"; depth:4; threshold:type both, track by_src, count 1, seconds 900; metadata: former_category MALWARE; reference:url,handlers.sans.org/wsalusky/rants/; reference:url,en.wikipedia.org/wiki/SOCKS; reference:url,ss5.sourceforge.net/socks4.protocol.txt; reference:url,ss5.sourceforge.net/socks4A.protocol.txt; reference:url,www.ietf.org/rfc/rfc1928.txt; reference:url,www.ietf.org/rfc/rfc1929.txt; reference:url,www.ietf.org/rfc/rfc1961.txt; reference:url,www.ietf.org/rfc/rfc3089.txt; reference:url,doc.emergingthreats.net/bin/view/Main/2003280; classtype:protocol-command-decode; sid:2003280; rev:6; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **SOCKSv4 Port 5050 Inbound Request (Windows Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,handlers.sans.org/wsalusky/rants/|url,en.wikipedia.org/wiki/SOCKS|url,ss5.sourceforge.net/socks4.protocol.txt|url,ss5.sourceforge.net/socks4A.protocol.txt|url,www.ietf.org/rfc/rfc1928.txt|url,www.ietf.org/rfc/rfc1929.txt|url,www.ietf.org/rfc/rfc1961.txt|url,www.ietf.org/rfc/rfc3089.txt|url,doc.emergingthreats.net/bin/view/Main/2003280

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001564
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO PUP/PUA OSSProxy HTTP Header"; flow:to_server,established; content:"X-OSSProxy|3a| OSSProxy"; http_header; threshold: type limit, count 5, seconds 300, track by_src; metadata: former_category INFO; reference:url,www.marketscore.com; reference:url,www.spysweeper.com/remove-marketscore.html; reference:url,doc.emergingthreats.net/bin/view/Main/2001564; classtype:policy-violation; sid:2001564; rev:12; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **PUP/PUA OSSProxy HTTP Header** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.marketscore.com|url,www.spysweeper.com/remove-marketscore.html|url,doc.emergingthreats.net/bin/view/Main/2001564

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 12

Category : ADWARE_PUP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024978
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Browser Plugin Detect - Observed in Apple Phishing"; flow:to_server,established; urilen:10; content:"POST"; http_method; content:"/ping.html"; http_uri; content:".html?appIdKey="; http_header; content:"data=eyJwbHVnaW4i"; http_client_body; depth:17; fast_pattern; pcre:"/^data=(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/Pi"; metadata: former_category INFO; classtype:bad-unknown; sid:2024978; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_11_08, updated_at 2017_11_08;)
` 

Name : **Browser Plugin Detect - Observed in Apple Phishing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-11-08

Last modified date : 2017-11-08

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013743
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious no-ip Domain"; dns_query; content:".no-ip."; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013743; rev:4; metadata:created_at 2011_10_05, updated_at 2019_08_29;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious no-ip Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-05

Last modified date : 2019-08-29

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022913
`alert http any any -> any any (msg:"ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel"; flow:established,to_server; content:"GET"; http_method; content:"/wpad.dat"; http_uri; fast_pattern; isdataat:!1,relative; reference:url,tools.ietf.org/html/draft-ietf-wrec-wpad-01; reference:url,ietf.org/rfc/rfc1002.txt; classtype:protocol-command-decode; sid:2022913; rev:3; metadata:created_at 2016_06_23, updated_at 2019_09_28;)
` 

Name : **WinHttp AutoProxy Request wpad.dat Possible BadTunnel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/draft-ietf-wrec-wpad-01|url,ietf.org/rfc/rfc1002.txt

CVE reference : Not defined

Creation date : 2016-06-23

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012171
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.org Domain"; dns_query; content:".3322.org"; nocase; isdataat:!1,relative; reference:url,isc.sans.edu/diary.html?storyid=3266; reference:url,isc.sans.edu/diary.html?storyid=5710; reference:url,google.com/safebrowsing/diagnostic?site=3322.org/; reference:url,www.mywot.com/en/scorecard/3322.org; classtype:misc-activity; sid:2012171; rev:7; metadata:created_at 2011_01_12, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,isc.sans.edu/diary.html?storyid=3266|url,isc.sans.edu/diary.html?storyid=5710|url,google.com/safebrowsing/diagnostic?site=3322.org/|url,www.mywot.com/en/scorecard/3322.org

CVE reference : Not defined

Creation date : 2011-01-12

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012758
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.dyndns. Domain"; dns_query; content:".dyndns."; nocase; classtype:misc-activity; sid:2012758; rev:5; metadata:created_at 2011_05_02, updated_at 2019_08_28;)
` 

Name : **DYNAMIC_DNS Query to *.dyndns. Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-02

Last modified date : 2019-08-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013097
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dyndns.* domain"; flow:established,to_server; content:".dyndns."; http_host; fast_pattern; content:!"checkip."; http_host; pcre:"/\.dyndns\.(biz|info|org|tv)$/W"; classtype:bad-unknown; sid:2013097; rev:8; metadata:created_at 2011_06_22, updated_at 2011_06_22;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dyndns.* domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-22

Last modified date : 2011-06-22

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016777
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.pw domain"; flow:established,to_server; content:".pw"; fast_pattern; http_host; isdataat:!1,relative; content:!"u.pw"; depth:4; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2016777; rev:12; metadata:created_at 2013_04_19, updated_at 2019_09_28;)
` 

Name : **HTTP Request to a *.pw domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-19

Last modified date : 2019-09-28

Rev version : 13

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016141
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Executable Download from dotted-quad Host"; flow:established,to_server; content:".exe"; http_uri; isdataat:!1,relative; nocase; content:"."; http_host; offset:1; depth:3; content:"."; http_host; within:4; content:"."; http_host; within:4; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}$/W"; http_request_line; content:".exe HTTP/1."; fast_pattern; classtype:trojan-activity; sid:2016141; rev:5; metadata:created_at 2013_01_03, updated_at 2019_09_28;)
` 

Name : **Executable Download from dotted-quad Host** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-03

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001562
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspected PUP/PUA User-Agent (OSSProxy)"; flow:established,to_server; content:"OSSProxy"; http_user_agent; threshold:type limit, count 2, seconds 300, track by_src; metadata: former_category INFO; reference:url,www.marketscore.com; reference:url,www.spysweeper.com/remove-marketscore.html; reference:url,doc.emergingthreats.net/2001562; classtype:policy-violation; sid:2001562; rev:35; metadata:created_at 2010_07_30, updated_at 2017_10_27;)
` 

Name : **Suspected PUP/PUA User-Agent (OSSProxy)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.marketscore.com|url,www.spysweeper.com/remove-marketscore.html|url,doc.emergingthreats.net/2001562

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-27

Rev version : 35

Category : ADWARE_PUP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014500
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.flnet.org Domain"; dns_query; content:".flnet.org"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014500; rev:5; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.flnet.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014788
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.3322.net"; flow:established,to_server; content:".3322.net"; http_host; isdataat:!1,relative; classtype:misc-activity; sid:2014788; rev:7; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.3322.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014492
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.dtdns.net Domain"; dns_query; content:".dtdns.net"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014492; rev:5; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.dtdns.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013684
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.dtdns.net domain"; flow:to_server,established; content:".dtdns.net"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2013684; rev:4; metadata:created_at 2011_09_21, updated_at 2019_09_28;)
` 

Name : **HTTP Request to a *.dtdns.net domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-21

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014493
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dtdns.net Domain"; flow:established,to_server; content:".dtdns.net"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2014493; rev:7; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dtdns.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013823
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.myftp.biz Domain"; dns_query; content:".myftp.biz"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013823; rev:3; metadata:created_at 2011_11_04, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.myftp.biz Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014784
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.8800.org"; dns_query; content:".8800.org"; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014784; rev:6; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.8800.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015634
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to Abused Domain *.mooo.com"; flow:established,to_server; content:".mooo.com"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2015634; rev:4; metadata:created_at 2012_08_16, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to Abused Domain *.mooo.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-08-16

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013096
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.dyndns-*.com domain"; flow:established,to_server; content:".dyndns-"; http_host; pcre:"/(?:at-home|at-work|blog|free|home|ip|mail|office|pics|remote|server|web|wiki|work)\.com/WR"; classtype:bad-unknown; sid:2013096; rev:5; metadata:created_at 2011_06_22, updated_at 2011_06_22;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.dyndns-*.com domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-22

Last modified date : 2011-06-22

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017645
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query Domain .bit"; dns_query; content:".bit"; nocase; isdataat:!1,relative; reference:url,www.normanshark.com/blog/necurs-cc-domains-non-censorable/; classtype:bad-unknown; sid:2017645; rev:3; metadata:created_at 2013_10_30, updated_at 2019_09_28;)
` 

Name : **DNS Query Domain .bit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.normanshark.com/blog/necurs-cc-domains-non-censorable/

CVE reference : Not defined

Creation date : 2013-10-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013744
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a no-ip Domain"; flow:established,to_server; content:".no-ip.com"; http_host; fast_pattern; content:!"www.no-ip.com"; http_host; classtype:bad-unknown; sid:2013744; rev:9; metadata:created_at 2011_10_05, updated_at 2011_10_05;)
` 

Name : **DYNAMIC_DNS HTTP Request to a no-ip Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-05

Last modified date : 2011-10-05

Rev version : 9

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022918
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.duckdns. Domain"; dns_query; content:".duckdns."; nocase; classtype:misc-activity; sid:2022918; rev:2; metadata:created_at 2016_06_27, updated_at 2019_08_28;)
` 

Name : **DYNAMIC_DNS Query to *.duckdns. Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-06-27

Last modified date : 2019-08-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012738
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.8866.org"; dns_query; content:".8866.org"; isdataat:!1,relative; nocase; reference:url,isc.sans.edu/diary.html?storyid=6739; reference:url,google.com/safebrowsing/diagnostic?site=8866.org/; reference:url,www.mywot.com/en/scorecard/8866.org; classtype:misc-activity; sid:2012738; rev:6; metadata:created_at 2011_04_28, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.8866.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,isc.sans.edu/diary.html?storyid=6739|url,google.com/safebrowsing/diagnostic?site=8866.org/|url,www.mywot.com/en/scorecard/8866.org

CVE reference : Not defined

Creation date : 2011-04-28

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014478
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.3d-game.com Domain"; dns_query; content:".3d-game.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014478; rev:5; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.3d-game.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018216
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Hopto.org"; flow:established,to_server; content:".hopto.org"; http_host; fast_pattern; isdataat:!1,relative; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018216; rev:3; metadata:created_at 2014_03_04, updated_at 2019_09_28;)
` 

Name : **HTTP Connection To DDNS Domain Hopto.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014037
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.osa.pl domain"; flow:established,to_server; content:".osa.pl"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2014037; rev:4; metadata:created_at 2011_12_22, updated_at 2019_09_28;)
` 

Name : **HTTP Request to a *.osa.pl domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-22

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024235
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query to Free Hosting Domain (freevnn . com)"; dns_query; content:".freevnn.com"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:md5,18c1c99412549815bdb89c36316243a7; classtype:bad-unknown; sid:2024235; rev:3; metadata:deployment Perimeter, signature_severity Minor, created_at 2017_04_21, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **DNS Query to Free Hosting Domain (freevnn . com)** 

Attack target : Not defined

Description : Alerts on DNS query for a domain related to free hosting service freevnn[.]com

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,18c1c99412549815bdb89c36316243a7

CVE reference : Not defined

Creation date : 2017-04-21

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2015820
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 7 User-Agent"; flow:established,to_server; content:"Windows NT 7"; nocase; http_user_agent; fast_pattern; classtype:trojan-activity; sid:2015820; rev:4; metadata:created_at 2012_10_19, updated_at 2012_10_19;)
` 

Name : **Suspicious Windows NT version 7 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-19

Last modified date : 2012-10-19

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018231
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS .scr file download"; flow:established,to_server; content:".scr"; http_uri; isdataat:!1,relative; fast_pattern; content:!"kaspersky.com"; http_host; metadata: former_category INFO; classtype:trojan-activity; sid:2018231; rev:5; metadata:created_at 2014_03_07, updated_at 2019_09_28;)
` 

Name : **SUSPICIOUS .scr file download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-03-07

Last modified date : 2019-09-28

Rev version : 6

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014511
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.suroot.com Domain"; flow:established,to_server; content:".suroot.com"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2014511; rev:5; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.suroot.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018213
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Myvnc.com"; flow:established,to_server; content:".myvnc.com"; http_host; isdataat:!1,relative; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018213; rev:3; metadata:created_at 2014_03_04, updated_at 2019_09_28;)
` 

Name : **HTTP Connection To DDNS Domain Myvnc.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014484
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.bbsindex.com Domain"; dns_query; content:".bbsindex.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014484; rev:5; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.bbsindex.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015633
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to Abused Domain *.mooo.com"; dns_query; content:".mooo.com"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2015633; rev:3; metadata:created_at 2012_08_16, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to Abused Domain *.mooo.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-08-16

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013213
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.3322.org"; flow:established,to_server; content:".3322.org"; http_host; isdataat:!1,relative; classtype:misc-activity; sid:2013213; rev:6; metadata:created_at 2011_07_06, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.3322.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-06

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023882
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.top domain"; flow:established,to_server; content:".top"; fast_pattern; http_host; pcre:"/^(\x3a\d{1,5})?$/WR"; threshold:type limit, track by_src, count 1, seconds 30; reference:url,www.symantec.com/connect/blogs/shady-tld-research-gdn-and-our-2016-wrap; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2023882; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_07, updated_at 2017_02_07;)
` 

Name : **HTTP Request to a *.top domain** 

Attack target : Client_Endpoint

Description : This signature matches on a .top domain TLD.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/connect/blogs/shady-tld-research-gdn-and-our-2016-wrap|url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2017-02-07

Last modified date : 2017-02-07

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017639
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Size Under 30K Size - Potentially Hostile"; flow:established,to_client; http_content_type; content:"application/java-archive"; depth:24; fast_pattern; http_content_len; byte_test:0,<=,30000,0,string,dec; file_data; content:"PK"; within:2; classtype:bad-unknown; sid:2017639; rev:7; metadata:created_at 2013_10_28, updated_at 2013_10_28;)
` 

Name : **JAR Size Under 30K Size - Potentially Hostile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-10-28

Last modified date : 2013-10-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024227
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Lets Encrypt Free SSL Cert Observed with IDN/Punycode Domain - Possible Phishing"; flow:established,from_server; tls_cert_subject; content:"xn--"; tls_cert_issuer; content:"O=Let's Encrypt"; metadata: former_category INFO; reference:url,isc.sans.edu/forums/diary/Tool+to+Detect+Active+Phishing+Attacks+Using+Unicode+LookAlike+Domains/22310/; reference:url,letsencrypt.org/about/; classtype:policy-violation; sid:2024227; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_04_19, updated_at 2017_04_19;)
` 

Name : **Lets Encrypt Free SSL Cert Observed with IDN/Punycode Domain - Possible Phishing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : policy-violation

URL reference : url,isc.sans.edu/forums/diary/Tool+to+Detect+Active+Phishing+Attacks+Using+Unicode+LookAlike+Domains/22310/|url,letsencrypt.org/about/

CVE reference : Not defined

Creation date : 2017-04-19

Last modified date : 2017-04-19

Rev version : 3

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018219
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.sytes.net Domain"; flow:established,to_server; content:".sytes.net"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2018219; rev:7; metadata:created_at 2012_03_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.sytes.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-05

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018359
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 2"; flow:established,to_server; content:"POST"; http_method; content:" Firefox/"; nocase; http_user_agent; fast_pattern; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; http_header_names; content:"|0d 0a|Host|0d 0a|"; depth:8; content:!"Accept-Encoding"; content:!"Referer"; content:!"X-Requested-With"; nocase; metadata: former_category INFO; classtype:bad-unknown; sid:2018359; rev:3; metadata:created_at 2014_04_04, updated_at 2017_12_01;)
` 

Name : **GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-04-04

Last modified date : 2017-12-01

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014473
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - Java Archive Download By Vulnerable Client"; flow:from_server,established; flowbits:isset,ET.http.javaclient.vulnerable; file_data; content:"PK"; depth:2; classtype:trojan-activity; sid:2014473; rev:5; metadata:created_at 2012_04_04, updated_at 2012_04_04;)
` 

Name : **JAVA - Java Archive Download By Vulnerable Client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-04

Last modified date : 2012-04-04

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013535
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.tc domain"; flow:established,to_server; content:".tc"; http_host; isdataat:!1,relative; classtype:bad-unknown; sid:2013535; rev:5; metadata:created_at 2011_09_06, updated_at 2019_09_28;)
` 

Name : **HTTP Request to a *.tc domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-06

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023458
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.gdn) - set"; flow:established,to_server; content:".gdn"; http_host; fast_pattern; pcre:"/^(?:\x3a\d{1,5})?$/W"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023458; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2017_10_12;)
` 

Name : **Possible EXE Download From Suspicious TLD (.gdn) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2017-10-12

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025098
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .gdn Domain"; dns_query; content:".gdn"; nocase; isdataat:!1,relative;  metadata: former_category HUNTING; classtype:bad-unknown; sid:2025098; rev:2; metadata:created_at 2017_12_02, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .gdn Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-02

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025097
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.gdn Domain"; flow:established,to_server; content:"POST"; http_method; content:".gdn"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025097; rev:2; metadata:created_at 2017_12_02, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.gdn Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-02

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025100
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.gq domain"; flow:established,to_server; content:"POST"; http_method; content:".gq"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025100; rev:1; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.gq domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025101
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.ga Domain"; flow:established,to_server; content:"POST"; http_method; content:".ga"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025101; rev:1; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.ga Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025102
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.ml Domain"; flow:established,to_server; content:"POST"; http_method; content:".ml"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025102; rev:1; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.ml Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025103
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.cf Domain"; flow:established,to_server; content:"POST"; http_method; content:".cf"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025103; rev:1; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.cf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025105
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .ga Domain"; dns_query; content:".ga"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025105; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .ga Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025106
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .ml Domain"; dns_query; content:".ml"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025106; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .ml Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025107
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .cf Domain"; dns_query; content:".cf"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025107; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .cf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025104
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .gq Domain"; dns_query; content:".gq"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025104; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .gq Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025109
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.ga) in TLS SNI"; flow:established,to_server; tls_sni; content:".ga"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025109; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.ga) in TLS SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025108
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.gq) in TLS SNI"; flow:established,to_server; tls_sni; content:".gq"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025108; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.gq) in TLS SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025110
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.ml) in TLS SNI"; flow:established,to_server; tls_sni; content:".ml"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025110; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.ml) in TLS SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025111
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.cf) in TLS SNI"; flow:established,to_server; tls_sni; content:".cf"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025111; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.cf) in TLS SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025112
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.gdn) in TLS SNI"; flow:established,to_server; tls_sni; content:".gdn"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025112; rev:2; metadata:created_at 2017_12_03, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.gdn) in TLS SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-03

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025122
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO MIPSEL File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".mipsel"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025122; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **MIPSEL File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025123
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO MIPS File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".mips"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025123; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **MIPS File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025124
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO ARM File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".arm"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025124; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **ARM File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025125
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO ARM7 File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".arm7"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025125; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **ARM7 File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025126
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO x86 File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".x86"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025126; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **x86 File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025127
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO m68k File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".m68k"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025127; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **m68k File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025128
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SPARC File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".sparc"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025128; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **SPARC File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025129
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO POWERPC File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".powerpc"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025129; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **POWERPC File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025130
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO X86_64 File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".x86_64"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025130; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **X86_64 File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025131
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUPERH File Download Request from IP Address"; flow:established,to_server; content:"GET"; http_method; content:".superh"; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}/W"; metadata: former_category INFO; classtype:bad-unknown; sid:2025131; rev:1; metadata:attack_target IoT, created_at 2017_12_05, updated_at 2019_09_28;)
` 

Name : **SUPERH File Download Request from IP Address** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-05

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022730
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PhishMe.com Phishing Landing Exercise"; flow:to_client,established; content:"200"; http_stat_code; content:"_phishme.com_session_id="; http_cookie; file_data; content:"<!-- ORGANIZATION LOGO"; nocase; fast_pattern; metadata: former_category INFO; classtype:trojan-activity; sid:2022730; rev:5; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2016_04_13, updated_at 2017_12_29;)
` 

Name : **PhishMe.com Phishing Landing Exercise** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods. A whitepaper concerning modern phishing obfuscation methods can be found at https://www.proofpoint.com/us/threat-insight/post/Obfuscation-Techniques-In-Phishing-Attacks

Tags : Phishing

Affected products : Not defined

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-04-13

Last modified date : 2017-12-29

Rev version : 5

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025189
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.ml)"; flow:established,to_client; tls_cert_subject; content:".ml"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2025189; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.ml)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025190
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.gdn)"; flow:established,to_client; tls_cert_subject; content:".gdn"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2025190; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.gdn)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025191
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.gq)"; flow:established,to_client; tls_cert_subject; content:".gq"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2025191; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.gq)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025192
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.ga)"; flow:established,to_client; tls_cert_subject; content:".ga"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2025192; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.ga)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025193
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.cf)"; flow:established,to_client; tls_cert_subject; content:".cf"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2025193; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.cf)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025194
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.xyz)"; flow:established,to_client; tls_cert_subject; content:".xyz"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2025194; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_09, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.xyz)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-09

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025231
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Multiple Javascript Unescapes - Common Obfuscation Observed in Phish Landing"; flow:established,to_client; file_data; content:"document.write(unescape"; fast_pattern; nocase; within:100; content:"document.write(unescape"; nocase; distance:0; content:"document.write(unescape"; nocase; distance:0; metadata: former_category INFO; classtype:bad-unknown; sid:2025231; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_01_22, updated_at 2018_01_22;)
` 

Name : **Multiple Javascript Unescapes - Common Obfuscation Observed in Phish Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-22

Last modified date : 2018-01-22

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025238
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Base64 Encoded powershell.exe in HTTP Response M1"; flow:established,from_server; content:"Content-Type|3a 20|text/plain"; http_header; file_data; content:"cG93ZXJzaGVsbC5leG"; fast_pattern; metadata: former_category INFO; reference:url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a; classtype:bad-unknown; sid:2025238; rev:3; metadata:created_at 2018_01_22, updated_at 2018_01_24;)
` 

Name : **Base64 Encoded powershell.exe in HTTP Response M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a

CVE reference : Not defined

Creation date : 2018-01-22

Last modified date : 2018-01-24

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025239
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Base64 Encoded powershell.exe in HTTP Response M2"; flow:established,from_server; content:"Content-Type|3a 20|text/plain"; http_header; file_data; content:"Bvd2Vyc2hlbGwuZXhl"; fast_pattern; reference:url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a; classtype:bad-unknown; sid:2025239; rev:3; metadata:created_at 2018_01_22, updated_at 2018_01_22;)
` 

Name : **Base64 Encoded powershell.exe in HTTP Response M2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a

CVE reference : Not defined

Creation date : 2018-01-22

Last modified date : 2018-01-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025240
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Base64 Encoded powershell.exe in HTTP Response M3"; flow:established,from_server; content:"Content-Type|3a 20|text/plain"; http_header; file_data; content:"wb3dlcnNoZWxsLmV4Z"; fast_pattern; reference:url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a; classtype:bad-unknown; sid:2025240; rev:3; metadata:created_at 2018_01_22, updated_at 2018_01_22;)
` 

Name : **Base64 Encoded powershell.exe in HTTP Response M3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,otx.alienvault.com/pulse/5a1348416dd9eb0c92d9897a

CVE reference : Not defined

Creation date : 2018-01-22

Last modified date : 2018-01-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025267
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Phishing Redirect 2018-01-30"; flow:established,to_client; file_data; content:"<html>|0d 0a|<body>|0d 0a|<script type=|22|text/JavaScript|22|>|0d 0a|<!--|0d 0a|"; nocase; depth:55; content:"setTimeout(|22|location.href|20|=|20 27|redirection.php?"; nocase; within:100; fast_pattern; pcre:"/^[a-z0-9_]{50,}/Ri"; content:"|27 3b 22|,0)|3b 0d 0a|-->|0d 0a|</script>|0d 0a|</body>"; nocase; within:100; metadata: former_category INFO; classtype:bad-unknown; sid:2025267; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_01_30, updated_at 2018_01_30;)
` 

Name : **Possible Phishing Redirect 2018-01-30** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-30

Last modified date : 2018-01-30

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024228
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious HTML Decimal Obfuscated Title - Possible Phishing Landing Apr 19 2017"; flow:from_server,established; content:"200"; http_stat_code; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<title>"; nocase; content:"|26 23|"; within:5; content:"|3b 26 23|"; fast_pattern; within:6; content:"|3b 26 23|"; within:6; content:"|3b 26 23|"; within:6; content:"|3b 26 23|"; within:6; content:"|3b 26 23|"; within:6; content:"|3b 26 23|"; within:6;  content:"</title>"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2024228; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_04_19, updated_at 2017_04_19;)
` 

Name : **Suspicious HTML Decimal Obfuscated Title - Possible Phishing Landing Apr 19 2017** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-04-19

Last modified date : 2017-04-19

Rev version : 3

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025317
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible MyEtherWallet Phishing Landing - SSL/TLS Certificate Observed"; flow:established,to_client; tls_cert_subject; content:"CN=xn--myeth"; depth:12; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2025317; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_02_06, updated_at 2018_02_06;)
` 

Name : **Possible MyEtherWallet Phishing Landing - SSL/TLS Certificate Observed** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-02-06

Last modified date : 2018-02-06

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025318
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible MyMonero Phishing Landing - SSL/TLS Certificate Observed"; flow:established,to_client; tls_cert_subject; content:"CN=xn--mymo"; depth:11; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2025318; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_02_06, updated_at 2018_02_06;)
` 

Name : **Possible MyMonero Phishing Landing - SSL/TLS Certificate Observed** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-02-06

Last modified date : 2018-02-06

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024420
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Request for .bin with BITS/ User-Agent"; flow:established,to_server; content:".bin"; http_uri; isdataat:!1,relative; content:"Microsoft BITS/"; http_user_agent; depth:15; fast_pattern; content:!"microsoft.com"; http_host; content:!"pdfcomplete.com"; http_host; content:!"mymitchell.com"; http_host; content:!"azureedge.net"; http_host; http_accept; content:"*/*"; depth:3; isdataat:!1,relative; http_header_names; content:!"Referer"; metadata: former_category MALWARE; classtype:bad-unknown; sid:2024420; rev:8; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Microsoft_Word, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_06_23, performance_impact Moderate, updated_at 2019_09_28;)
` 

Name : **Request for .bin with BITS/ User-Agent** 

Attack target : Client_Endpoint

Description : Alerts on download request from a malicious Microsoft Office Word document. In the past an Ursnif payload was downloaded.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-06-23

Last modified date : 2019-09-28

Rev version : 9

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2025399
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Browser Plugin Detect - Observed in Phish Landings"; flow:established,to_client; file_data; content:"#browser_info"; content:"getBrowserMajorVersion()"; nocase; distance:0; fast_pattern; content:"#os_info"; nocase; distance:0; content:"getOSVersion()"; nocase; distance:0; content:"getScreenPrint()"; nocase; distance:0; content:"getPlugins()"; nocase; distance:0; content:"getJavaVersion()"; nocase; distance:0; content:"getFlashVersion()"; nocase; distance:0; content:"getSilverlightVersion()"; nocase; distance:0; metadata: former_category INFO; classtype:bad-unknown; sid:2025399; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_02_26, updated_at 2018_02_26;)
` 

Name : **Suspicious Browser Plugin Detect - Observed in Phish Landings** 

Attack target : Client_Endpoint

Description : JS Plugin Detect 

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-02-26

Last modified date : 2018-02-26

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025411
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Secondary Flash Request Seen (no alert)"; flow:established,to_server; http_referer; content:"/[[DYNAMIC]]/1"; fast_pattern; http_header_names; content:"x-flash-version"; flowbits:set,ET.SecondaryFlash.Req; flowbits:noalert; metadata: former_category INFO; classtype:trojan-activity; sid:2025411; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Sundown_EK, signature_severity Major, created_at 2018_03_09, updated_at 2018_03_09;)
` 

Name : **Secondary Flash Request Seen (no alert)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Sundown EK

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-03-09

Last modified date : 2018-03-09

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025428
`alert http any any -> any any (msg:"ET INFO Possible Sandvine PacketLogic Injection"; flow:established,from_server; id:13330; flags:AF; content:"HTTP/1.1 307 Temporary Redirect|0a|Location|3a 20|"; depth:42; fast_pattern; content:"Connection: close|0a 0a|"; distance:0; isdataat:!1,relative; metadata: former_category INFO; reference:url,citizenlab.ca/2018/03/bad-traffic-sandvines-packetlogic-devices-deploy-government-spyware-turkey-syria/; classtype:misc-activity; sid:2025428; rev:1; metadata:attack_target Client_and_Server, deployment Datacenter, signature_severity Minor, created_at 2018_03_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Possible Sandvine PacketLogic Injection** 

Attack target : Client_and_Server

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,citizenlab.ca/2018/03/bad-traffic-sandvines-packetlogic-devices-deploy-government-spyware-turkey-syria/

CVE reference : Not defined

Creation date : 2018-03-13

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026657
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed Free Hosting Domain (*.000webhostapp .com in DNS Lookup)"; dns_query; content:".000webhostapp.com"; nocase; isdataat:!1,relative; metadata: former_category INFO; classtype:not-suspicious; sid:2026657; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2018_03_16, performance_impact Moderate, updated_at 2019_09_28;)
` 

Name : **Observed Free Hosting Domain (*.000webhostapp .com in DNS Lookup)** 

Attack target : Client_Endpoint

Description : This will alert on a DNS query for a domain hosted on a free hosting servcie 000webhost.com, which has been abused by malicious actors.

Tags : Not defined

Affected products : Any

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-03-16

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2026658
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed SSL Cert for Free Hosting Domain (*.000webhostapp .com)"; flow:established,to_client; tls_cert_subject; content:"CN=*.000webhostapp.com"; nocase; isdataat:!1,relative; metadata: former_category INFO; classtype:not-suspicious; sid:2026658; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2018_03_16, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed SSL Cert for Free Hosting Domain (*.000webhostapp .com)** 

Attack target : Client_Endpoint

Description : This will alert on the presence of an ssl cert for the free hosting site 000webapphost.com, which has been observed as being abused.

Tags : Not defined

Affected products : Any

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-03-16

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025436
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious User-Agent (CustomStringHere)"; flow:established,to_server; content:"CustomStringHere"; http_user_agent; metadata: former_category INFO; reference:md5,7a8cb1223e006bc7e70169c060d7057b; classtype:misc-activity; sid:2025436; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_03_19, updated_at 2018_03_19;)
` 

Name : **Suspicious User-Agent (CustomStringHere)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : md5,7a8cb1223e006bc7e70169c060d7057b

CVE reference : Not defined

Creation date : 2018-03-19

Last modified date : 2018-03-19

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025460
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO NYU Internet HTTP/SSL Census Scan"; flow:to_server,established; content:"NYU Internet Census (https://scan.lol|3b 20|research@scan.lol)"; http_user_agent; metadata: former_category INFO; reference:url,scan.lol; classtype:network-scan; sid:2025460; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Minor, created_at 2018_04_03, updated_at 2018_04_03;)
` 

Name : **NYU Internet HTTP/SSL Census Scan** 

Attack target : Web_Server

Description : NYU Internet Scanning

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : network-scan

URL reference : url,scan.lol

CVE reference : Not defined

Creation date : 2018-04-03

Last modified date : 2018-04-03

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025519
`alert tcp any any -> any 4786 (msg:"ET INFO Cisco Smart Install Protocol Observed"; flow:established,only_stream; content:"|00 00 00 01 00 00 00 01|"; depth:8; metadata: former_category INFO; reference:url,www.us-cert.gov/ncas/alerts/TA18-106A; classtype:misc-activity; sid:2025519; rev:1; metadata:attack_target Networking_Equipment, deployment Perimeter, deployment Internal, signature_severity Minor, created_at 2018_04_20, updated_at 2018_04_20;)
` 

Name : **Cisco Smart Install Protocol Observed** 

Attack target : Networking_Equipment

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.us-cert.gov/ncas/alerts/TA18-106A

CVE reference : Not defined

Creation date : 2018-04-20

Last modified date : 2018-04-20

Rev version : 1

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025553
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible Rogue LoJack Asset Tracking Agent"; flow:established,to_server; content:"POST"; http_method; urilen:1; content:"TagId|3a 20|"; http_header; fast_pattern; content:!".namequery.com|0d 0a|"; http_header; threshold: type limit, count 2, seconds 300, track by_src; metadata: former_category INFO; reference:url,asert.arbornetworks.com/lojack-becomes-a-double-agent/amp/; classtype:misc-attack; sid:2025553; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_05_02, updated_at 2018_05_02;)
` 

Name : **Possible Rogue LoJack Asset Tracking Agent** 

Attack target : Client_Endpoint

Description : Alerts on Lojack checkin to non Absolute Software Corp C2

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,asert.arbornetworks.com/lojack-becomes-a-double-agent/amp/

CVE reference : Not defined

Creation date : 2018-05-02

Last modified date : 2018-05-02

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015671
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Adobe PDF in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"%PDF-"; within:6; flowbits:set,ET.pdf.in.http; flowbits:noalert; reference:cve,CVE-2008-2992; reference:bugtraq,30035; reference:secunia,29773; classtype:not-suspicious; sid:2015671; rev:10; metadata:created_at 2010_09_25, updated_at 2010_09_25;)
` 

Name : **Adobe PDF in HTTP Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : cve,CVE-2008-2992|bugtraq,30035|secunia,29773

CVE reference : Not defined

Creation date : 2010-09-25

Last modified date : 2010-09-25

Rev version : 10

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025560
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .myq-see .com DDNS Domain"; dns_query; content:".myq-see.com"; nocase; isdataat:!1,relative; metadata: former_category INFO; classtype:policy-violation; sid:2025560; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_05_07, performance_impact Moderate, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .myq-see .com DDNS Domain** 

Attack target : Client_Endpoint

Description : This will alert on a machine making a query to a known DDNS domain which might be abused by malware.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-05-07

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2025985
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Adobe PDX in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"%PDX-"; within:5; flowbits:set,ET.pdx.in.http; flowbits:noalert; metadata: former_category INFO; classtype:not-suspicious; sid:2025985; rev:2; metadata:affected_product Adobe_Reader, deployment Perimeter, signature_severity Informational, created_at 2018_08_10, performance_impact Low, updated_at 2018_08_10;)
` 

Name : **Adobe PDX in HTTP Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Adobe_Reader

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-08-10

Last modified date : 2018-08-10

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2016394
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Adobe Flash Uncompressed in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"FWS"; within:3; flowbits:set,HTTP.UncompressedFlash; flowbits:noalert; metadata: former_category INFO; classtype:not-suspicious; sid:2016394; rev:7; metadata:deployment Perimeter, signature_severity Informational, created_at 2013_02_08, performance_impact Low, updated_at 2018_08_10;)
` 

Name : **Adobe Flash Uncompressed in HTTP Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-08

Last modified date : 2018-08-10

Rev version : 7

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025986
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INFO MP3 with ID3 in HTTP Flowbit Set"; flow:from_server,established; file_data; content:"ID3"; within:3; content:"|FB FF|"; distance:0; flowbits:set,ET.mp3.in.http; flowbits:noalert; metadata: former_category INFO; classtype:not-suspicious; sid:2025986; rev:1; metadata:affected_product Adobe_Flash, deployment Perimeter, signature_severity Informational, created_at 2018_08_10, performance_impact Low, updated_at 2018_08_10;)
` 

Name : **MP3 with ID3 in HTTP Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Adobe_Flash

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-08-10

Last modified date : 2018-08-10

Rev version : 1

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026074
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Inbound PowerShell Checking for Virtual Host (Win32_Fan WMI)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Get-WmiObject -Query"; nocase; content:"Select|20|*|20|from|20|win32_fan"; fast_pattern; nocase; metadata: former_category INFO; reference:url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/; classtype:trojan-activity; sid:2026074; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag Enumeration, tag Anti_VM, signature_severity Major, created_at 2018_09_05, performance_impact Low, updated_at 2018_09_05;)
` 

Name : **Inbound PowerShell Checking for Virtual Host (Win32_Fan WMI)** 

Attack target : Client_and_Server

Description : Detects on an inbound PowerShell script containing a WMI query for Win32_Fan.  Virtual environments and some physical setups will return nothing, implying it is a virtualized environment.  This has been seen ITW used by the Middle East APT group, OilRig.

Tags : Anti-VM, Enumeration, PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/

CVE reference : Not defined

Creation date : 2018-09-05

Last modified date : 2018-09-05

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026075
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Inbound PowerShell Checking for Virtual Host (MSAcpi_ThermalZoneTemperature WMI)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Get-WmiObject -Query"; nocase; content:"Select|20|*|20|from|20|MSAcpi_ThermalZoneTemperature"; fast_pattern; nocase; metadata: former_category INFO; reference:url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/; classtype:trojan-activity; sid:2026075; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag Enumeration, tag Anti_VM, signature_severity Major, created_at 2018_09_05, performance_impact Low, updated_at 2018_09_05;)
` 

Name : **Inbound PowerShell Checking for Virtual Host (MSAcpi_ThermalZoneTemperature WMI)** 

Attack target : Client_and_Server

Description : Detects on an inbound PowerShell script containing a WMI query for MSAcpi_ThermalZoneTemperature.  Virtual environments and some physical setups will return nothing, implying it is a virtualized environment.  This has been seen ITW used by the Middle East APT group, OilRig.

Tags : Anti-VM, Enumeration, PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/

CVE reference : Not defined

Creation date : 2018-09-05

Last modified date : 2018-09-05

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026076
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Inbound PowerShell Checking for Virtual Host (Win32_PointingDevice WMI)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Get-WmiObject -Query"; nocase; content:"Select|20|*|20|from|20|Win32_PointingDevice"; fast_pattern; nocase; content:"-contains|20|"; pcre:"/^\x22(?:v(mware|irtual|irtualbox|m\x20ware|box))/Rsi"; metadata: former_category INFO; reference:url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/; classtype:trojan-activity; sid:2026076; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag Enumeration, tag Anti_VM, signature_severity Major, created_at 2018_09_05, performance_impact Low, updated_at 2018_09_05;)
` 

Name : **Inbound PowerShell Checking for Virtual Host (Win32_PointingDevice WMI)** 

Attack target : Client_and_Server

Description : Detects on an inbound PowerShell script containing a WMI query for Win32_PointingDevice and a search for strings related to virtualization (VMware, Virtual, Virtualbox etc).  Virtual environments and some physical setups will return nothing, implying it is a virtualized environment.  This has been seen ITW used by the Middle East APT group, OilRig.

Tags : Anti-VM, Enumeration, PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/

CVE reference : Not defined

Creation date : 2018-09-05

Last modified date : 2018-09-05

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026077
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Inbound PowerShell Checking for Virtual Host (Win32_DiskDevice WMI)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Get-WmiObject -Query"; nocase; content:"Select|20|*|20|from|20|Win32_DiskDevice"; fast_pattern; nocase; content:"-contains|20|"; pcre:"/^\x22(?:v(mware|irtual|irtualbox|m\x20ware|box))/Rsi"; metadata: former_category INFO; reference:url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/; classtype:trojan-activity; sid:2026077; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag Enumeration, tag Anti_VM, signature_severity Major, created_at 2018_09_05, performance_impact Low, updated_at 2018_09_05;)
` 

Name : **Inbound PowerShell Checking for Virtual Host (Win32_DiskDevice WMI)** 

Attack target : Client_and_Server

Description : Detects on an inbound PowerShell script containing a WMI query for Win32_DiskDevice and a search for strings related to virtualization (VMware, Virtual, Virtualbox etc).  Virtual environments and some physical setups will return nothing, implying it is a virtualized environment.  This has been seen ITW used by the Middle East APT group, OilRig.

Tags : Anti-VM, Enumeration, PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/

CVE reference : Not defined

Creation date : 2018-09-05

Last modified date : 2018-09-05

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026078
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Inbound PowerShell Checking for Virtual Host (Win32_BaseBoard WMI)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Get-WmiObject -Query"; nocase; content:"Select|20|*|20|from|20|Win32_BaseBoard"; fast_pattern; nocase; content:"-contains|20|"; pcre:"/^\x22(?:v(mware|irtual|irtualbox|m\x20ware|box))/Rsi"; metadata: former_category INFO; reference:url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/; classtype:trojan-activity; sid:2026078; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag Enumeration, tag Anti_VM, signature_severity Major, created_at 2018_09_05, performance_impact Low, updated_at 2018_09_05;)
` 

Name : **Inbound PowerShell Checking for Virtual Host (Win32_BaseBoard WMI)** 

Attack target : Client_and_Server

Description : Detects on an inbound PowerShell script containing a WMI query for Win32_BaseBoard.  Virtual environments and some physical setups will return nothing, implying it is a virtualized environment.  This has been seen ITW used by the Middle East APT group, OilRig.


Tags : Anti-VM, Enumeration, PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/

CVE reference : Not defined

Creation date : 2018-09-05

Last modified date : 2018-09-05

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026413
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible System Enumeration via WMI Queries (AntiVirusProduct)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"On|20|Error|20|Resume|20|Next|0d 0a|"; depth:25; content:"SELECT|20 2a 20|FROM|20|AntiVirusProduct"; distance:0; fast_pattern; nocase; threshold:type limit, count 1, seconds 60, track by_src; metadata: former_category INFO; reference:md5,11f792cc617cf5c08603d4da829a1fa9; classtype:policy-violation; sid:2026413; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag VBS, tag Enumeration, signature_severity Major, created_at 2018_09_26, performance_impact Low, updated_at 2018_09_28;)
` 

Name : **Possible System Enumeration via WMI Queries (AntiVirusProduct)** 

Attack target : Client_and_Server

Description : Alerts on an inbound VBS utilizing WMI queries to determine what AntiVirus software is installed on the infected system, typically used by malware to determine what AntiVirus is installed.

Tags : Enumeration, VBS

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : md5,11f792cc617cf5c08603d4da829a1fa9

CVE reference : Not defined

Creation date : 2018-09-26

Last modified date : 2018-09-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026414
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible System Enumeration via WMI Queries (AntiSpywareProduct)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"On|20|Error|20|Resume|20|Next|0d 0a|"; depth:25; content:"SELECT|20 2a 20|FROM|20|AntiSpywareProduct"; distance:0; fast_pattern; nocase; threshold:type limit, count 1, seconds 60, track by_src; metadata: former_category INFO; reference:md5,11f792cc617cf5c08603d4da829a1fa9; classtype:policy-violation; sid:2026414; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag VBS, tag Enumeration, signature_severity Major, created_at 2018_09_26, performance_impact Low, updated_at 2018_09_28;)
` 

Name : **Possible System Enumeration via WMI Queries (AntiSpywareProduct)** 

Attack target : Client_and_Server

Description : Alerts on an inbound VBS utilizing WMI queries to determine what AntiSpyware software is installed on the infected system, typically used by malware to determine what AntiSpyware is installed.

Tags : Enumeration, VBS

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : md5,11f792cc617cf5c08603d4da829a1fa9

CVE reference : Not defined

Creation date : 2018-09-26

Last modified date : 2018-09-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026415
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible System Enumeration via WMI Queries (FirewallProduct)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"On|20|Error|20|Resume|20|Next|0d 0a|"; depth:25; content:"SELECT|20 2a 20|FROM|20|FirewallProduct"; distance:0; fast_pattern; nocase; threshold:type limit, count 1, seconds 60, track by_src; metadata: former_category INFO; reference:md5,11f792cc617cf5c08603d4da829a1fa9; classtype:policy-violation; sid:2026415; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag VBS, tag Enumeration, signature_severity Major, created_at 2018_09_26, performance_impact Low, updated_at 2018_09_28;)
` 

Name : **Possible System Enumeration via WMI Queries (FirewallProduct)** 

Attack target : Client_and_Server

Description : Alerts on an inbound VBS utilizing WMI queries to determine what firewall software is installed on the infected system, typically used by malware to determine what firewall is installed.

Tags : Enumeration, VBS

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : md5,11f792cc617cf5c08603d4da829a1fa9

CVE reference : Not defined

Creation date : 2018-09-26

Last modified date : 2018-09-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026420
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Generic 000webhostapp.com POST 2018-09-27 (set)"; flow:to_server,established; content:"POST"; http_method; content:".000webhostapp.com"; http_host; isdataat:!1,relative; fast_pattern; flowbits:set,ET.000webhostpost; flowbits:noalert; metadata: former_category INFO; classtype:misc-attack; sid:2026420; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2018_09_27, updated_at 2019_09_28;)
` 

Name : **Generic 000webhostapp.com POST 2018-09-27 (set)** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-09-27

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026427
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possibly Malicious VBS Writing to Persistence Registry Location"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"on|20|error|20|resume|20|next"; nocase; content:".regwrite|20 22|"; distance:0; content:"|5c|software|5c|microsoft|5c|windows|5c|currentversion|5c|run"; distance:0; within:80; fast_pattern; metadata: former_category INFO; reference:md5,cac1aedbcb417dcba511db5caae4b8c0; classtype:trojan-activity; sid:2026427; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag VBS, tag Persistence, signature_severity Major, created_at 2018_09_28, performance_impact Low, updated_at 2018_09_28;)
` 

Name : **Possibly Malicious VBS Writing to Persistence Registry Location** 

Attack target : Client_and_Server

Description : Alerts on inbound VBS that is writing to a registry key in a common persistence location.  When the infected system is rebooted, whatever was written by the VBS will be executed.  This is common malicious behaviour.

Tags : Persistence, VBS

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,cac1aedbcb417dcba511db5caae4b8c0

CVE reference : Not defined

Creation date : 2018-09-28

Last modified date : 2018-09-28

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2016379
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Containing Executable Downloaded"; flow:established,to_client; flowbits:isset,ET.http.javaclient; file_data; content:"PK"; within:2; content:".exe"; fast_pattern; nocase; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2016379; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2013_02_08, updated_at 2018_10_09;)
` 

Name : **JAR Containing Executable Downloaded** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-08

Last modified date : 2018-10-09

Rev version : 6

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026515
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Redirect to Download EXE from Bitbucket"; flow:established,to_client; content:"302"; http_stat_code; content:"Location|3a 20|https://bitbucket.org"; http_header; content:".exe|0d 0a|"; http_header; distance:0; metadata: former_category INFO; classtype:bad-unknown; sid:2026515; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_10_17, updated_at 2018_10_17;)
` 

Name : **Suspicious Redirect to Download EXE from Bitbucket** 

Attack target : Client_Endpoint

Description : Suspicious Redirect to Download EXE from Bitbucket

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-17

Last modified date : 2018-10-17

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026569
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO GET to Puu.sh for TXT File with Minimal Headers"; flow:to_server,established; content:"GET"; http_method; content:".txt"; http_uri; nocase; isdataat:!1,relative; content:"puu.sh"; http_host; depth:6; isdataat:!1,relative; fast_pattern; http_header_names; content:"|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; depth:22; isdataat:!1,relative; metadata: former_category INFO; classtype:bad-unknown; sid:2026569; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_11_02, updated_at 2019_09_28;)
` 

Name : **GET to Puu.sh for TXT File with Minimal Headers** 

Attack target : Client_Endpoint

Description : Informational alert for txt file. Have seen malware using this to DL config/instructions/info

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-11-02

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026570
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possibly Suspicious Request for Putty.exe from Non-Standard Download Location"; flow:to_server,established; content:"GET"; http_method; content:"/putty.exe"; http_uri; nocase; isdataat:!1,relative; content:!"the.earth.li"; http_host; metadata: former_category INFO; classtype:bad-unknown; sid:2026570; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_11_02, updated_at 2019_09_28;)
` 

Name : **Possibly Suspicious Request for Putty.exe from Non-Standard Download Location** 

Attack target : Client_Endpoint

Description : putty.exe is a commonly trojaned/faked file that appears in many malware downloads

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-11-02

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026643
`alert tcp $HOME_NET any -> any 22 (msg:"ET INFO Plaintext SSH Authentication Identified (Encryption set to None)"; flow:established,to_server; content:"|00 00 00|"; content:"|00 00 00|"; distance:0; within:50; content:"|0e|ssh-connection|00 00 00 08|password|00 00 00 00|"; distance:0; within:31; content:"|00 00 00 00 00 00 00 00 00|"; distance:0; metadata: former_category INFO; reference:url,hamwan.org/Standards/Network%20Engineering/Authentication/SSH%20Without%20Encryption.html; classtype:attempted-user; sid:2026643; rev:2; metadata:attack_target Client_and_Server, deployment Perimeter, deployment Internal, signature_severity Major, created_at 2018_11_21, performance_impact Low, updated_at 2018_11_21;)
` 

Name : **Plaintext SSH Authentication Identified (Encryption set to None)** 

Attack target : Client_and_Server

Description : Alerts on an SSH authentication with encryption cipher set to 'None'.  Some Mikrotik routers ship with this as the default setting.

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,hamwan.org/Standards/Network%20Engineering/Authentication/SSH%20Without%20Encryption.html

CVE reference : Not defined

Creation date : 2018-11-21

Last modified date : 2018-11-21

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026674
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Minimal HTTP GET Request to Bit.ly"; flow:established,to_server; content:"GET"; http_method; http_start; content:"HTTP/1.1|0d 0a|Host|3a 20|bit.ly|0d 0a|Connection|3a 20|Keep-Alive|0d 0a 0d 0a|"; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2026674; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_11_29, updated_at 2019_09_28;)
` 

Name : **Minimal HTTP GET Request to Bit.ly** 

Attack target : Client_Endpoint

Description : Suspicious minimal request to bit.ly - usually has accept, referer, etc

GET /********* HTTP/1.1
Host: bit.ly
User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-11-29

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026684
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Certificate with Unknown Content M2"; flow:established,to_client; file_data; content:"-----BEGIN CERTIFICATE-----|0A|"; depth:28; fast_pattern; byte_test:1,!=,0x4D,0,relative; metadata: former_category INFO; reference:url,blog.nviso.be/2018/07/31/powershell-inside-a-certificate-part-1/; classtype:misc-activity; sid:2026684; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2018_12_04, performance_impact Moderate, updated_at 2018_12_04;)
` 

Name : **Certificate with Unknown Content M2** 

Attack target : Client_Endpoint

Description : This will alert on a certificate being sent to a client with a non-standard content within the certificate, which could be indicative of a malicious act.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : url,blog.nviso.be/2018/07/31/powershell-inside-a-certificate-part-1/

CVE reference : Not defined

Creation date : 2018-12-04

Last modified date : 2018-12-04

Rev version : 1

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2026649
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Certificate with Unknown Content M1"; flow:established,to_client; file_data; content:"-----BEGIN CERTIFICATE-----|0D 0A|"; depth:29; fast_pattern; byte_test:1,!=,0x4D,0,relative; metadata: former_category INFO; reference:url,blog.nviso.be/2018/07/31/powershell-inside-a-certificate-part-1/; classtype:misc-activity; sid:2026649; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_11_26, performance_impact Moderate, updated_at 2018_11_26;)
` 

Name : **Certificate with Unknown Content M1** 

Attack target : Client_Endpoint

Description : This will alert on a certificate banner inbound with non-standard certificate contents following.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : url,blog.nviso.be/2018/07/31/powershell-inside-a-certificate-part-1/

CVE reference : Not defined

Creation date : 2018-11-26

Last modified date : 2018-11-26

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2026746
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Fake Login - Possible Phishing - 2018-12-31"; flow:established,to_server; content:"POST"; http_method; content:"fakeLogin="; depth:10; nocase; http_client_body; content:"&fakePassword="; nocase; distance:0; http_client_body; fast_pattern; metadata: former_category INFO; classtype:suspicious-login; sid:2026746; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2018_12_31, updated_at 2018_12_31;)
` 

Name : **Suspicious Fake Login - Possible Phishing - 2018-12-31** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : suspicious-login

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-12-31

Last modified date : 2018-12-31

Rev version : 2

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026747
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO maas.io Image Download Flowbit Set"; flow:established,to_server; content:"GET"; http_method; content:"maas/2.3."; http_user_agent; content:"images.maas.io"; http_host; flowbits:set,ET.Maas.Site.Download; flowbits:noalert; metadata: former_category INFO; classtype:trojan-activity; sid:2026747; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, signature_severity Informational, created_at 2019_01_02, updated_at 2019_01_02;)
` 

Name : **maas.io Image Download Flowbit Set** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-01-02

Last modified date : 2019-01-02

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026758
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO External Host Probing for ChromeCast Devices"; flow:established,to_server; content:"GET"; http_method; urilen:18; content:"/setup/eureka_info"; http_uri; fast_pattern; metadata: former_category INFO; reference:url,www.theverge.com/2019/1/2/18165386/pewdiepie-chromecast-hack-tseries-google-chromecast-smart-tv; classtype:trojan-activity; sid:2026758; rev:2; metadata:attack_target IoT, deployment Perimeter, tag Enumeration, signature_severity Minor, created_at 2019_01_04, performance_impact Low, updated_at 2019_01_04;)
` 

Name : **External Host Probing for ChromeCast Devices** 

Attack target : IoT

Description : Alerts on an inbound HTTP GET request containing the API call used to disclose device information on ChromeCast devices.

Tags : Enumeration

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.theverge.com/2019/1/2/18165386/pewdiepie-chromecast-hack-tseries-google-chromecast-smart-tv

CVE reference : Not defined

Creation date : 2019-01-04

Last modified date : 2019-01-04

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026774
`#alert tls $HOME_NET any -> $EXTERNAL_NET 853 (msg:"ET INFO DNS Over TLS Request Outbound"; flow:established,to_server; content:"|16 03 01 01|"; depth:4; metadata: former_category INFO; reference:url,www.linuxbabe.com/ubuntu/ubuntu-stubby-dns-over-tls; classtype:trojan-activity; sid:2026774; rev:2; metadata:created_at 2019_01_10, updated_at 2019_01_10;)
` 

Name : **DNS Over TLS Request Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.linuxbabe.com/ubuntu/ubuntu-stubby-dns-over-tls

CVE reference : Not defined

Creation date : 2019-01-10

Last modified date : 2019-01-10

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026863
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible RTF File With Obfuscated Version Header"; flow:established,to_client; file_data; content:"{|5C|rt"; within:4; content:!"f"; within:1; metadata: former_category INFO; classtype:bad-unknown; sid:2026863; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_01_30, updated_at 2019_01_30;)
` 

Name : **Possible RTF File With Obfuscated Version Header** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-01-30

Last modified date : 2019-01-30

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026887
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST Request to Suspicious *.icu domain"; flow:established,to_server; content:"POST"; http_method; content:".icu"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026887; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_02_06, updated_at 2019_09_28;)
` 

Name : **HTTP POST Request to Suspicious *.icu domain** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-06

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026888
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query for Suspicious .icu Domain"; dns_query; content:".icu"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026888; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_02_06, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .icu Domain** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-06

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026889
`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Domain (*.icu) in TLS SNI"; flow:established,to_server; tls_sni; content:".icu"; isdataat:!1,relative; fast_pattern; nocase; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026889; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_02_06, updated_at 2019_09_28;)
` 

Name : **Suspicious Domain (*.icu) in TLS SNI** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-06

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026890
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Let's Encrypt Certificate for Suspicious TLD (.icu)"; flow:established,to_client; tls_cert_subject; content:".icu"; isdataat:!1,relative; tls_cert_issuer; content:"Let's Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2026890; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_02_06, updated_at 2019_09_28;)
` 

Name : **Observed Let's Encrypt Certificate for Suspicious TLD (.icu)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-06

Last modified date : 2019-09-28

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026891
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.icu) - set"; flow:established,to_server; content:".icu"; http_host; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.icu(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2026891; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_02_06, updated_at 2019_02_06;)
` 

Name : **Possible EXE Download From Suspicious TLD (.icu) - set** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-02-06

Last modified date : 2019-02-06

Rev version : 1

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026988
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell NoProfile Command Received In Powershell Stagers"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"-nop"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026988; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Minor, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell NoProfile Command Received In Powershell Stagers** 

Attack target : Not defined

Description : Alerts on inbound PowerShell with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026989
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell Hidden Window Command Common In Powershell Stagers M1"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"-w"; nocase; distance:0; content:"hidden"; within:17; metadata: former_category INFO; classtype:trojan-activity; sid:2026989; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell Hidden Window Command Common In Powershell Stagers M1** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026990
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell Hidden Window Command Common In Powershell Stagers M2"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"-w 1"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026990; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell Hidden Window Command Common In Powershell Stagers M2** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026991
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell NonInteractive Command Common In Powershell Stagers"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"-noni"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026991; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell NonInteractive Command Common In Powershell Stagers** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026993
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell Base64 Encoded Content Command Common In Powershell Stagers M2"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"FromBase64String|28|"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026993; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell Base64 Encoded Content Command Common In Powershell Stagers M2** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026994
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell DownloadFile Command Common In Powershell Stagers"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"DownloadFile|28|"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026994; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell DownloadFile Command Common In Powershell Stagers** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026995
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell DownloadString Command Common In Powershell Stagers"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"DownloadString|28|"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026995; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell DownloadString Command Common In Powershell Stagers** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026996
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell DownloadData Command Common In Powershell Stagers"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"DownloadData|28|"; nocase; distance:0; metadata: former_category INFO; classtype:trojan-activity; sid:2026996; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_02_28;)
` 

Name : **PowerShell DownloadData Command Common In Powershell Stagers** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-02-28

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026992
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell Base64 Encoded Content Command Common In Powershell Stagers M1"; flow:established,from_server; file_data; content:"powershell"; fast_pattern; nocase; content:"|20|-e"; nocase; distance:0; pcre:"/^(?:nc)?\s*(?:[A-Z0-9+\/]{4})*(?:[A-Z0-9+\/]{2}==|[A-Z0-9+\/]{3}=)/Ri"; metadata: former_category INFO; classtype:trojan-activity; sid:2026992; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, tag PowerShell, signature_severity Major, created_at 2019_02_28, performance_impact Low, updated_at 2019_03_05;)
` 

Name : **PowerShell Base64 Encoded Content Command Common In Powershell Stagers M1** 

Attack target : Not defined

Description : Alerts on inbound PowerShell via HTTP with suspicious parameters.

Tags : PowerShell

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-02-28

Last modified date : 2019-03-05

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2025627
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO [eSentire] Possible Kali Linux Updates"; flow:established,to_server; content:"GET"; http_method; content:"APT-HTTP|2f|"; http_user_agent; content:"kali.org"; http_host; fast_pattern; pcre:"/^[a-z0-9.]+\.kali\.org/W"; metadata: former_category INFO; classtype:policy-violation; sid:2025627; rev:2; metadata:affected_product Linux, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_06_25, updated_at 2018_06_25;)
` 

Name : **[eSentire] Possible Kali Linux Updates** 

Attack target : Client_Endpoint

Description : Kali Update via APT

Tags : Not defined

Affected products : Linux

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-06-25

Last modified date : 2018-06-25

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027076
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Wget Request for Executable"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; isdataat:!1,relative; nocase; content:"Wget/"; depth:5; http_user_agent; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027076; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_03_12, updated_at 2019_09_28;)
` 

Name : **Wget Request for Executable** 

Attack target : Client_Endpoint

Description : Informative Signature for WGET to EXE

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-03-12

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017886
`alert smtp any any -> $SMTP_SERVERS any (msg:"ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment"; flow:established; content:"|0D 0A 0D 0A|TV"; content:"AAAAAAAAAAAAAAAA"; within:200; metadata: former_category INFO; classtype:bad-unknown; sid:2017886; rev:3; metadata:created_at 2013_12_19, updated_at 2019_03_27;)
` 

Name : **SUSPICIOUS SMTP EXE - EXE SMTP Attachment** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-19

Last modified date : 2019-03-27

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027207
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request with Double Cache-Control"; flow:established,to_server; content:"Cache-Control|3a 20|no-cache|0d 0a|Cache-Control|3a 20|no-cache"; http_header; classtype:trojan-activity; sid:2027207; rev:1; metadata:created_at 2019_04_16, updated_at 2019_04_16;)
` 

Name : **HTTP Request with Double Cache-Control** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-16

Last modified date : 2019-04-16

Rev version : 1

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027287
`alert dns $HOME_NET any -> any 53 (msg:"ET INFO DYNAMIC_DNS Query to *.myddns.me Domain"; flow:established,to_server; dns_query; content:".myddns.me"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category INFO; classtype:policy-violation; sid:2027287; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag DynamicDNS, signature_severity Informational, created_at 2019_04_25, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.myddns.me Domain** 

Attack target : Client_Endpoint

Description : This will alert on a DNS query to a known dynamic DNS provider domain.

Tags : DynamicDNS

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-25

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027288
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.myddns.me Domain"; flow:established,to_server; content:".myddns.me"; http_host; isdataat:!1,relative; metadata: former_category INFO; classtype:policy-violation; sid:2027288; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, tag DynamicDNS, signature_severity Informational, created_at 2019_04_25, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.myddns.me Domain** 

Attack target : Client_Endpoint

Description : This rule alerts on HTTP traffic to a known Dyanmic DNS Provider domain

Tags : DynamicDNS

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-25

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027299
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.autoddns .com Domain"; dns_query; content:".autoddns.com"; nocase; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 120; metadata: former_category INFO; classtype:policy-violation; sid:2027299; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag DynamicDNS, signature_severity Informational, created_at 2019_04_30, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.autoddns .com Domain** 

Attack target : Client_Endpoint

Description : This will alert on a DNS query to a known dynamic DNS provider domain.

Tags : DynamicDNS

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-30

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027300
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.autoddns.com Domain"; flow:established,to_server; content:".autoddns.com"; http_host; isdataat:!1,relative; metadata: former_category INFO; classtype:policy-violation; sid:2027300; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, tag DynamicDNS, signature_severity Informational, created_at 2019_04_30, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.autoddns.com Domain** 

Attack target : Client_Endpoint

Description : This rule alerts on HTTP traffic to a known Dyanmic DNS Provider domain

Tags : DynamicDNS

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-30

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027323
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Anyplace Remote Access Initial Connection Attempt (005)"; flow:established,to_server; content:"HTTP|2f|1.1|20|005|0d 0a|VERSION|3a 20|"; depth:23; content:"PLATFORM|3a 20|"; distance:0; content:"IPADDRESS|3a 20|"; distance:0; fast_pattern; metadata: former_category INFO; reference:md5,30e4f96590d530ba5dc1762f8b87c16b; classtype:trojan-activity; sid:2027323; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, deployment Internal, tag RAT, signature_severity Major, created_at 2019_05_07, malware_family Anyplace, performance_impact Low, updated_at 2019_05_07;)
` 

Name : **Anyplace Remote Access Initial Connection Attempt (005)** 

Attack target : Not defined

Description : Alerts on TCP traffic containing keywords observed in Anyplace Remote Access Tool samples.

Tags : RAT

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,30e4f96590d530ba5dc1762f8b87c16b

CVE reference : Not defined

Creation date : 2019-05-07

Last modified date : 2019-05-07

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Anyplace

Type : SID

Performance Impact : Low

# 2027324
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Anyplace Remote Access Checkin (051)"; flow:established,to_server; content:"HTTP|2f|1.1|20|051"; depth:12; content:"VER|3a 20|"; distance:0; content:"OBJ|3a 20|"; distance:0; content:"FUNC|3a 20|"; distance:0; content:"NAME|3a 20|"; distance:0; content:"ACC|3a 20|"; distance:0; content:"SRV|3a 20|"; distance:0; content:"PRODUCT|3a 20|"; distance:0; fast_pattern; metadata: former_category INFO; reference:md5,30e4f96590d530ba5dc1762f8b87c16b; classtype:trojan-activity; sid:2027324; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, deployment Internal, tag RAT, signature_severity Major, created_at 2019_05_07, malware_family Anyplace, performance_impact Low, updated_at 2019_05_07;)
` 

Name : **Anyplace Remote Access Checkin (051)** 

Attack target : Not defined

Description : Alerts on TCP traffic containing keywords observed in Anyplace Remote Access Tool samples.

Tags : RAT

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,30e4f96590d530ba5dc1762f8b87c16b

CVE reference : Not defined

Creation date : 2019-05-07

Last modified date : 2019-05-07

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Anyplace

Type : SID

Performance Impact : Low

# 2007994
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious User-Agent (1 space)"; flow:to_server,established; content:"User-Agent|3a 20 0d 0a|"; http_header; content:!".mcafee.com"; http_host; content:!"deezer.com"; http_host; isdataat:!1,relative; content:!"googlezip.net"; http_host; content:!"metrics.tbliab.net"; http_host; isdataat:!1,relative; content:!"dajax.com"; http_host; isdataat:!1,relative; content:!"update.eset.com"; http_host; isdataat:!1,relative; content:!".sketchup.com"; http_host; isdataat:!1,relative; content:!".yieldmo.com"; http_host; isdataat:!1,relative; content:!"ping-start.com"; http_host; isdataat:!1,relative; content:!".bluekai.com"; http_host; content:!".stockstracker.com"; http_host; content:!".doubleclick.net"; http_host; content:!".pingstart.com"; http_host; content:!".colis-logistique.com"; http_host; content:!"android-lrcresource.wps.com"; http_host; content:!"track.package-buddy.com"; http_host; content:!"talkgadget.google.com"; http_host; isdataat:!1,relative; content:!".visualstudio.com"; http_host; isdataat:!1,relative; content:!".slack-edge.com"; http_host; isdataat:!1,relative; content:!".slack.com"; http_host; isdataat:!1,relative; content:!".lifesizecloud.com"; http_host; isdataat:!1,relative; metadata: former_category INFO; reference:url,doc.emergingthreats.net/bin/view/Main/2007994; classtype:unknown; sid:2007994; rev:21; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent (1 space)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007994

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 22

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027360
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO AutoIt User-Agent Downloading ZIP"; flow:established,to_server; content:"GET"; http_method; content:".zip"; nocase; http_uri; isdataat:!1,relative; content:"AutoIt"; http_user_agent; depth:6; isdataat:!1,relative; fast_pattern; http_header_names; content:!"Referer"; metadata: former_category INFO; classtype:trojan-activity; sid:2027360; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_05_17, updated_at 2019_09_28;)
` 

Name : **AutoIt User-Agent Downloading ZIP** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-17

Last modified date : 2019-09-28

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016537
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO GET Minimal HTTP Headers Flowbit Set"; flow:established,to_server; content:"GET"; http_method; http_header_names; content:!"Accept"; content:!"If-"; content:!"Referer"; content:!"User-Agent"; content:!"Content"; flowbits:set,min.gethttp; flowbits:noalert; classtype:bad-unknown; sid:2016537; rev:3; metadata:created_at 2013_03_05, updated_at 2019_05_21;)
` 

Name : **GET Minimal HTTP Headers Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-05

Last modified date : 2019-05-21

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025162
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Request for Doc to IP Address with Terse Headers"; flow:established,to_server; content:"GET"; http_method; content:".doc"; fast_pattern; nocase; http_uri; isdataat:!1,relative; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}$/W"; http_header_names; content:"|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; isdataat:!1,relative; metadata: former_category INFO; classtype:bad-unknown; sid:2025162; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2017_12_21, updated_at 2019_09_28;)
` 

Name : **Suspicious Request for Doc to IP Address with Terse Headers** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-12-21

Last modified date : 2019-09-28

Rev version : 4

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027394
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO PowerShell Internet Connectivity Check via Network GUID Inbound"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|3a 3a|GetTypeFromCLSID"; nocase; content:"|5b|Guid|5d 27 7b|DCB00C01-570F-4A9B-8D69-199FDBA5723B|7d 27 29 29|.IsConnectedToInternet"; distance:0; nocase; fast_pattern; metadata: former_category INFO; reference:md5,036180b14dce975a055e62902e5f3567; classtype:trojan-activity; sid:2027394; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag PowerShell, tag T1086, signature_severity Major, created_at 2019_05_29, performance_impact Low, updated_at 2019_05_29;)
` 

Name : **PowerShell Internet Connectivity Check via Network GUID Inbound** 

Attack target : Client_and_Server

Description : Alerts on an inbound PowerShell script with a unique method of testing network connectivity.

Tags : PowerShell, T1086

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,036180b14dce975a055e62902e5f3567

CVE reference : Not defined

Creation date : 2019-05-29

Last modified date : 2019-05-29

Rev version : 1

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2022054
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible MSXMLHTTP Request to Dotted Quad"; flow:to_server,established; pcre:"/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/W"; http_start; content:"HTTP/1.1|0d 0a|Accept|3a 20|*/*|0d 0a|Accept-Encoding|3a 20|gzip, deflate|0d 0a|User-Agent|3a 20|Mozilla/4.0 (compatible|3b 20|MSIE 7.0|3b 20|Windows NT"; fast_pattern; http_header_names; content:!"UA-CPU"; content:!"Cookie"; content:!"Referer"; content:!"Accept-Language"; flowbits:set,et.MS.XMLHTTP.ip.request; flowbits:noalert; classtype:misc-activity; sid:2022054; rev:4; metadata:created_at 2015_11_09, updated_at 2019_06_03;)
` 

Name : **Possible MSXMLHTTP Request to Dotted Quad** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-09

Last modified date : 2019-06-03

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027471
`alert dns any any -> $HOME_NET any (msg:"ET INFO Suspicious Registrar Nameservers in DNS Response (carbon2u)"; content:"|00 02 00 01|"; content:"|03|ns1|08|carbon2u|03|com|00|"; distance:14; within:18; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027471; rev:1; metadata:deployment Perimeter, signature_severity Major, created_at 2019_06_14, performance_impact Low, updated_at 2019_06_14;)
` 

Name : **Suspicious Registrar Nameservers in DNS Response (carbon2u)** 

Attack target : Not defined

Description : Alerts on an inbound nameserver observed hosting mostly evil domains (Magecart related, June 2019).

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-14

Last modified date : 2019-06-14

Rev version : 1

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2019935
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO AutoIt User Agent Executable Request"; flow:established,to_server; content:"GET"; http_method; content:".exe"; nocase; http_uri; isdataat:!1,relative; content:"AutoIt"; http_user_agent; depth:6; isdataat:!1,relative; fast_pattern; http_header_names; content:!"Referer"; metadata: former_category INFO; classtype:trojan-activity; sid:2019935; rev:5; metadata:deployment Perimeter, tag AutoIt, signature_severity Informational, created_at 2014_12_15, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **AutoIt User Agent Executable Request** 

Attack target : Not defined

Description : Not defined

Tags : AutoIt

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-15

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027519
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned EWE Telecom Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://login-tk.ewe.de/"; distance:4; within:25; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027519; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned EWE Telecom Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027520
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned La Banque Postale FR Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://voscomptesenligne.labanquepostale.fr/"; distance:4; within:46; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027520; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned La Banque Postale FR Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027521
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned ATB Bank Online Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.atbonline.com/"; distance:4; within:27; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027521; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned ATB Bank Online Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027522
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned RBC Royal Bank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www1.royalbank.com/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027522; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned RBC Royal Bank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027523
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned CIBC Bank Page - Possible Phishing Landing M1"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.cibc.mobi/"; distance:4; within:23; fast_pattern; classtype:bad-unknown; sid:2027523; rev:1; metadata:created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned CIBC Bank Page - Possible Phishing Landing M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027524
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned ABSA Bank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://ib.absa.co.za/"; distance:4; within:23; fast_pattern; classtype:bad-unknown; sid:2027524; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned ABSA Bank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027525
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Instagram Page - Possible Phishing Landing M1"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.instagram.com/"; distance:4; within:27; fast_pattern; classtype:bad-unknown; sid:2027525; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Instagram Page - Possible Phishing Landing M1** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027526
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Instagram Page - Possible Phishing Landing M2"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://instagram.com/"; distance:4; within:23; fast_pattern; classtype:bad-unknown; sid:2027526; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Instagram Page - Possible Phishing Landing M2** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027527
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Spotify Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.spotify.com/"; distance:4; within:25; fast_pattern; classtype:bad-unknown; sid:2027527; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Spotify Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027528
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned ADP Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://runpayroll.adp.com/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027528; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned ADP Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027529
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Westpac Bank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://bank.westpac.co.nz/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027529; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Westpac Bank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027530
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Simplii Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://mobile.simplii.com/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027530; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Simplii Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027531
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned CIBC Bank Page - Possible Phishing Landing M2"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.cibconline.cibc.com/"; distance:4; within:33; fast_pattern; classtype:bad-unknown; sid:2027531; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned CIBC Bank Page - Possible Phishing Landing M2** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027532
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Chase Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://secure05c.chase.com/"; distance:4; within:29; fast_pattern; classtype:bad-unknown; sid:2027532; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Chase Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027533
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Scotiabank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.scotiaonline.scotiabank.com/"; distance:4; within:41; fast_pattern; classtype:bad-unknown; sid:2027533; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Scotiabank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027534
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Cox Page - Possible Phishing Landing M1"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.cox.com/"; distance:4; within:21; fast_pattern; classtype:bad-unknown; sid:2027534; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Cox Page - Possible Phishing Landing M1** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027535
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Cox Page - Possible Phishing Landing M2"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://idm.east.cox.net/"; distance:4; within:26; fast_pattern; classtype:bad-unknown; sid:2027535; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Cox Page - Possible Phishing Landing M2** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027536
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Comcast / Xfinity Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://idm.xfinity.com/"; distance:4; within:25; fast_pattern; classtype:bad-unknown; sid:2027536; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Comcast / Xfinity Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027537
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Telstra Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.my.telstra.com.au/"; distance:4; within:31; fast_pattern; classtype:bad-unknown; sid:2027537; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Telstra Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027538
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Comcast / Xfinity Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://login.xfinity.com/"; distance:4; within:27; fast_pattern; classtype:bad-unknown; sid:2027538; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Comcast / Xfinity Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027539
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Itscom Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://webmail.itscom.net/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027539; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Itscom Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027540
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Bank of America Page - Possible Phishing Landing M1"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://staticweb.bankofamerica.com/"; distance:4; within:37; fast_pattern; classtype:bad-unknown; sid:2027540; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Bank of America Page - Possible Phishing Landing M1** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027541
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Bank of America Page - Possible Phishing Landing M2"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://www.bankofamerica.com/"; distance:4; within:31; fast_pattern; classtype:bad-unknown; sid:2027541; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Bank of America Page - Possible Phishing Landing M2** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027542
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Bank of America Page - Possible Phishing Landing M3"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://secure.bankofamerica.com/"; distance:4; within:34; fast_pattern; classtype:bad-unknown; sid:2027542; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Bank of America Page - Possible Phishing Landing M3** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027543
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Microsoft Office Apps Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://odc.officeapps.live.com/"; distance:4; within:33; fast_pattern; classtype:bad-unknown; sid:2027543; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Microsoft Office Apps Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027544
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Telekom / Tmobile Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://accounts.login.idm.telekom.com/"; distance:4; within:40; fast_pattern; classtype:bad-unknown; sid:2027544; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Telekom / Tmobile Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027545
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Fidelity Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://login.fidelity.com/"; distance:4; within:28; fast_pattern; classtype:bad-unknown; sid:2027545; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Fidelity Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027546
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Societe Generale FR Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- saved from url=("; within:500; content:")https://particuliers.societegenerale.fr/"; distance:4; within:41; fast_pattern; classtype:bad-unknown; sid:2027546; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Societe Generale FR Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027547
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Impots Gouv FR Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from cfspart.impots.gouv.fr"; within:500; classtype:bad-unknown; sid:2027547; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Impots Gouv FR Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027548
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Godaddy Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from sso.godaddy.com"; within:500; classtype:bad-unknown; sid:2027548; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Godaddy Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027549
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Dropbox Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from www.dropbox.com"; within:500; classtype:bad-unknown; sid:2027549; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Dropbox Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027550
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned American Express Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from online.americanexpress.com"; within:500; classtype:bad-unknown; sid:2027550; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned American Express Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027551
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned ABSA Bank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from ib.absa.co.za"; within:500; classtype:bad-unknown; sid:2027551; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned ABSA Bank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027552
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Match Dating Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from secure.match.com"; within:500; classtype:bad-unknown; sid:2027552; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Match Dating Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027553
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Telekom / Tmobile Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from accounts.login.idm.telekom.com"; within:500; classtype:bad-unknown; sid:2027553; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Telekom / Tmobile Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027554
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned South State Bank Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from www.southstatebank.com"; within:500; classtype:bad-unknown; sid:2027554; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned South State Bank Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027555
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Google Tools Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from tools.google.com"; within:500; classtype:bad-unknown; sid:2027555; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Google Tools Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027556
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Yahoo Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from login.yahoo.com"; within:500; classtype:bad-unknown; sid:2027556; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Yahoo Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027557
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Discover Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from card.discover.com"; within:500; classtype:bad-unknown; sid:2027557; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Discover Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027558
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Linkedin Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from www.linkedin.com"; within:500; classtype:bad-unknown; sid:2027558; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Linkedin Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027559
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned NAB Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from ib.nab.com.au"; within:500; classtype:bad-unknown; sid:2027559; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned NAB Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027560
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Cloned Ziggo NL Page - Possible Phishing Landing"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"<!-- mirrored from www.ziggo.nl"; within:500; classtype:bad-unknown; sid:2027560; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Cloned Ziggo NL Page - Possible Phishing Landing** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027562
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible Phishing Landing - Zeus365 Encoding"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"|3c 21 2d 2d 20 68 74 6d 6c 20 65 6e 63 72 79 70 74 69 6f 6e 20 70 72 6f 76 69 64 65 64 20 62 79 20 7a 65 75 73 33 36 35 20 2d 2d 3e|"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2027562; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Possible Phishing Landing - Zeus365 Encoding** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027621
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SSL/TLS Certificate Observed (Lucy Phishing Awareness Default Certificate)"; flow:established,to_client; tls_cert_issuer; content:"C=CH, ST=Thalwil, L=Thalwil, O=LUCY Phishing GmbH, OU=LUCY Phishing GmbH"; metadata: former_category INFO; reference:url,cdn.riskiq.com/wp-content/uploads/2019/06/Gift-Cardsharks-Intelligence-Report-2019-RiskIQ.pdf; reference:url,lucysecurity.com; classtype:misc-activity; sid:2027621; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_06_26, performance_impact Low, updated_at 2019_06_27;)
` 

Name : **SSL/TLS Certificate Observed (Lucy Phishing Awareness Default Certificate)** 

Attack target : Client_Endpoint

Description : Signature fires on the default certificate used by Lucy, from Lucy Security, a phishing awareness platform also used in malicious attacks.

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,cdn.riskiq.com/wp-content/uploads/2019/06/Gift-Cardsharks-Intelligence-Report-2019-RiskIQ.pdf|url,lucysecurity.com

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-27

Rev version : 2

Category : PHISHING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2013220
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a 3322.net Domain *.8866.org"; flow:established,to_server; content:"8866.org"; http_host; isdataat:!1,relative; reference:url,www.mywot.com/en/scorecard/8866.org; classtype:misc-activity; sid:2013220; rev:5; metadata:created_at 2011_07_06, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS HTTP Request to a 3322.net Domain *.8866.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.mywot.com/en/scorecard/8866.org

CVE reference : Not defined

Creation date : 2011-07-06

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012612
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Hiloti Style GET to PHP with invalid terse MSIE headers"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"Mozilla/4.0|20|(compatible|3b 20|MSIE|20|"; http_user_agent; content:!"8"; within:1; http_user_agent; content:"|3b 20|Windows|20|NT|20|"; http_user_agent; distance:0; content:!".taobao.com"; http_host; content:!".dict.cn"; http_host; content:!".avg.com"; http_host; content:!"SlimBrowser"; http_user_agent; content:!".weather.hao.360.cn"; content:!"es.f.360.cn"; http_host; http_host; http_header_names; content:"|0d 0a|User-Agent|0d 0a|Host|0d 0a|"; depth:20; fast_pattern; metadata: former_category TROJAN; classtype:trojan-activity; sid:2012612; rev:17; metadata:created_at 2011_03_31, updated_at 2019_08_05;)
` 

Name : **Hiloti Style GET to PHP with invalid terse MSIE headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2019-08-05

Rev version : 15

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027863
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .biz TLD"; dns_query; content:".biz"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027863; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .biz TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027864
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .okinawa TLD"; dns_query; content:".okinawa"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027864; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .okinawa TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027865
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns_query; content:".cloud"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027865; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .cloud TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027866
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .desi TLD"; dns_query; content:".desi"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027866; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .desi TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027867
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .life TLD"; dns_query; content:".life"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027867; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .life TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027868
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .work TLD"; dns_query; content:".work"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027868; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .work TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027869
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .ryukyu TLD"; dns_query; content:".ryukyu"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027869; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .ryukyu TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027870
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .world TLD"; dns_query; content:".world"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027870; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .world TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027871
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .fit TLD"; dns_query; content:".fit"; nocase; isdataat:!1,relative; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027871; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_08_13, updated_at 2019_09_28;)
` 

Name : **Observed DNS Query to .fit TLD** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027872
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.biz Domain"; flow:established,to_server; content:".biz"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027872; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_08_13;)
` 

Name : **HTTP Request to Suspicious *.biz Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-08-13

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027873
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.okinawa Domain"; flow:established,to_server; content:".okinawa"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027873; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.okinawa Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027874
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.cloud Domain"; flow:established,to_server; content:".cloud"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027874; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.cloud Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027875
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.desi Domain"; flow:established,to_server; content:".desi"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027875; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.desi Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027876
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.life Domain"; flow:established,to_server; content:".life"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027876; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.life Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027877
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.work Domain"; flow:established,to_server; content:".work"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027877; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.work Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027878
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.ryukyu Domain"; flow:established,to_server; content:".ryukyu"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027878; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.ryukyu Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027879
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.world Domain"; flow:established,to_server; content:".world"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027879; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.world Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027880
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to Suspicious *.fit Domain"; flow:established,to_server; content:".fit"; fast_pattern; http_host; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2027880; rev:2; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_08_13, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **HTTP Request to Suspicious *.fit Domain** 

Attack target : Not defined

Description : Alerts on an outbound HTTP request to a suspicious TLD ranked in the Spamhaus top 10 most abused TLDs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2019-08-13

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2003626
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Double User-Agent (User-Agent User-Agent)"; flow:established,to_server; content:"User-Agent|3a 20|"; depth:12; nocase; http_user_agent; content:!"SogouMobileTool"; nocase; http_user_agent; content:!".lge.com"; http_host; content:!".kugou.com"; http_host; metadata: former_category ADWARE_PUP; reference:url,doc.emergingthreats.net/bin/view/Main/2003626; classtype:bad-unknown; sid:2003626; rev:16; metadata:created_at 2010_07_30, updated_at 2019_08_13;)
` 

Name : **Double User-Agent (User-Agent User-Agent)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003626

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-13

Rev version : 16

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018812
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.myredirect.us Domain (Sitelutions)"; dns_query; content:".myredirect.us"; nocase; fast_pattern; isdataat:!1,relative; classtype:bad-unknown; sid:2018812; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.myredirect.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018810
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.passinggas.net Domain (Sitelutions)"; dns_query; content:".passinggas.net"; nocase; fast_pattern; isdataat:!1,relative; classtype:bad-unknown; sid:2018810; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.passinggas.net Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018814
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.rr.nu Domain (Sitelutions)"; dns_query; content:".rr.nu"; nocase; fast_pattern; isdataat:!1,relative; classtype:bad-unknown; sid:2018814; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.rr.nu Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018816
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.kwik.to Domain (Sitelutions)"; dns_query; content:".kwik.to"; nocase; isdataat:!1,relative; fast_pattern; classtype:bad-unknown; sid:2018816; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.kwik.to Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018818
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *.myfw.us Domain (Sitelutions)"; dns_query; content:".myfw.us"; nocase; isdataat:!1,relative; fast_pattern; classtype:bad-unknown; sid:2018818; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *.myfw.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018820
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *ontheweb.nu Domain (Sitelutions)"; dns_query; content:".ontheweb.nu"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018820; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *ontheweb.nu Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018822
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *isthebe.st Domain (Sitelutions)"; dns_query; content:".isthebe.st"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018822; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *isthebe.st Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018824
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *byinter.net Domain (Sitelutions)"; dns_query; content:".byinter.net"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018824; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *byinter.net Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018826
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *findhere.org Domain (Sitelutions)"; dns_query; content:".findhere.org"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018826; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *findhere.org Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018828
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *onthenetas.com Domain (Sitelutions)"; dns_query; content:".onthenetas.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018828; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *onthenetas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018830
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *uglyas.com Domain (Sitelutions)"; dns_query; content:".uglyas.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018830; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *uglyas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018832
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *assexyas.com Domain (Sitelutions)"; dns_query; content:".assexyas.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018832; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *assexyas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018834
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *passas.us Domain (Sitelutions)"; dns_query; content:".passas.us"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018834; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *passas.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018836
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *atthissite.com Domain (Sitelutions)"; dns_query; content:"athissite.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018836; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *atthissite.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018838
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *athersite.com Domain (Sitelutions)"; dns_query; content:"athersite.com"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018838; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *athersite.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018840
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *isgre.at Domain (Sitelutions)"; dns_query; content:".isgre.at"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018840; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *isgre.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018842
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *lookin.at Domain (Sitelutions)"; dns_query; content:".lookin.at"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018842; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *lookin.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018844
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *bestdeals.at Domain (Sitelutions)"; dns_query; content:".bestdeals.at"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018844; rev:2; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *bestdeals.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018846
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to *lowestprices Domain (Sitelutions)"; dns_query; content:".lowestprices.at"; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018846; rev:4; metadata:created_at 2014_07_30, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to *lowestprices Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013845
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.ez-dns.com Domain"; dns_query; content:".ez-dns.com"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013845; rev:4; metadata:created_at 2011_11_04, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.ez-dns.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013863
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.dyndns-web.com Domain"; dns_query; content:".dyndns-web.com"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013863; rev:5; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.dyndns-web.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013971
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query for Suspicious .dyndns-at-home.com Domain"; dns_query; content:".dyndns-at-home.com"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013971; rev:5; metadata:created_at 2011_11_28, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query for Suspicious .dyndns-at-home.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-28

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014480
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.4irc.com Domain"; dns_query; content:".4irc.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014480; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.4irc.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014482
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.b0ne.com Domain"; dns_query; content:".b0ne.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014482; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.b0ne.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014486
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.chatnook.com Domain"; dns_query; content:".chatnook.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014486; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.chatnook.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014488
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.darktech.org Domain"; dns_query; content:".darktech.org"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014488; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.darktech.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014490
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.deaftone.com Domain"; dns_query; content:".deaftone.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014490; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.deaftone.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014494
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.effers.com Domain"; dns_query; content:".effers.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014494; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.effers.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014496
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.etowns.net Domain"; dns_query; content:".etowns.net"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014496; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.etowns.net Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014498
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.etowns.org Domain"; dns_query; content:".etowns.org"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014498; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.etowns.org Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014502
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.gotgeeks.com Domain"; dns_query; content:".gotgeeks.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014502; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.gotgeeks.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014504
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.scieron.com Domain"; dns_query; content:".scieron.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014504; rev:6; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.scieron.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014506
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.slyip.com Domain"; dns_query; content:".slyip.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014506; rev:7; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.slyip.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014510
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.suroot.com Domain"; dns_query; content:".suroot.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014510; rev:7; metadata:created_at 2012_04_05, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.suroot.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-05

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014779
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.2288.org"; dns_query; content:".2288.org"; fast_pattern; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014779; rev:8; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.2288.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 9

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014781
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.3322.net"; dns_query; content:".3322.net"; fast_pattern; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014781; rev:8; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.3322.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 9

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014782
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.6600.org"; dns_query; content:".6600.org"; fast_pattern; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014782; rev:8; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.6600.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 9

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014783
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.7766.org"; dns_query; content:".7766.org"; fast_pattern; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014783; rev:8; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.7766.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 9

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014786
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to 3322.net Domain *.9966.org"; dns_query; content:".9966.org"; fast_pattern; isdataat:!1,relative; threshold: type limit, count 1, track by_src, seconds 300; classtype:misc-activity; sid:2014786; rev:7; metadata:created_at 2012_05_18, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to 3322.net Domain *.9966.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-18

Last modified date : 2019-09-28

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014868
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to dns-stuff.com Domain *.dns-stuff.com"; dns_query; content:".dns-stuff.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2014868; rev:4; metadata:created_at 2012_06_07, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to dns-stuff.com Domain *.dns-stuff.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-06-07

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018366
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a *.mrbasic.com Domain"; dns_query; content:".mrbasic.com"; fast_pattern; nocase; isdataat:!1,relative; classtype:bad-unknown; sid:2018366; rev:4; metadata:created_at 2014_04_04, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a *.mrbasic.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-04-04

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013843
`alert dns $HOME_NET any -> any any (msg:"ET INFO DNS Query to a Suspicious *.orge.pl Domain"; dns_query; content:".orge.pl"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013843; rev:4; metadata:created_at 2011_11_04, updated_at 2019_09_28;)
` 

Name : **DNS Query to a Suspicious *.orge.pl Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022382
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.dnsip.ru Domain"; dns_query; content:".dnsip.ru"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2022382; rev:3; metadata:created_at 2016_01_19, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.dnsip.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022383
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.dyn-dns.ru Domain"; dns_query; content:".dyn-dns.ru"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2022383; rev:4; metadata:created_at 2016_01_19, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.dyn-dns.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022381
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.dnsalias.ru Domain"; dns_query; content:".dnsalias.ru"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2022381; rev:4; metadata:created_at 2016_01_19, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.dnsalias.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022384
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious *.dns-free.ru Domain"; dns_query; content:".dns-free.com"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2022384; rev:4; metadata:created_at 2016_01_19, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious *.dns-free.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-01-19

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022876
`alert dns $HOME_NET any -> any any (msg:"ET INFO DYNAMIC_DNS Query to a Suspicious dynapoint.pw Domain"; dns_query; content:"dynapoint.pw"; depth:12; isdataat:!1,relative; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2022876; rev:3; metadata:created_at 2016_06_08, updated_at 2019_09_28;)
` 

Name : **DYNAMIC_DNS Query to a Suspicious dynapoint.pw Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-06-08

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027945
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO McAfee AV Download - Set"; flow:established,to_server; content:"GET"; http_method; content:"McHttpH"; http_user_agent; fast_pattern; content:"download.mcafee.com"; http_host; flowbits:set,ET.Mcafee.Site.Download; flowbits:noalert; metadata: former_category INFO; classtype:not-suspicious; sid:2027945; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_09_05, performance_impact Moderate, updated_at 2019_09_05;)
` 

Name : **McAfee AV Download - Set** 

Attack target : Client_Endpoint

Description : This will alert on traffic stemming from McAfee AV.

Tags : Not defined

Affected products : Any

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-09-05

Last modified date : 2019-09-05

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2015848
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Imposter USPS Domain"; flow:established,to_server; content:".usps.com."; http_host; fast_pattern; classtype:bad-unknown; sid:2015848; rev:3; metadata:created_at 2012_10_26, updated_at 2019_09_09;)
` 

Name : **Imposter USPS Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-26

Last modified date : 2019-09-09

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016696
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious svchost.exe in URI - Possible Process Dump/Trojan Download"; flow:established,to_server; content:"GET"; http_method; content:"/svchost.exe"; http_uri; nocase; fast_pattern; isdataat:!1,relative; metadata: former_category INFO; classtype:bad-unknown; sid:2016696; rev:14; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious svchost.exe in URI - Possible Process Dump/Trojan Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016700
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious explorer.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/explorer.exe"; http_uri; nocase; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; reference:md5,de1bc32ad135b14ad3a5cf72566a63ff; classtype:bad-unknown; sid:2016700; rev:14; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious explorer.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,de1bc32ad135b14ad3a5cf72566a63ff

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016697
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious winlogin.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/winlogon.exe"; http_uri; nocase; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; reference:md5,fd95cc0bb7d3ea5a0c86d45570df5228; reference:md5,09330c596a33689a610a1b183a651118; classtype:bad-unknown; sid:2016697; rev:14; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious winlogin.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,fd95cc0bb7d3ea5a0c86d45570df5228|md5,09330c596a33689a610a1b183a651118

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016698
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious services.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/services.exe"; http_uri; nocase; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; reference:md5,145c06300d61b3a0ce2c944fe7cdcb96; classtype:bad-unknown; sid:2016698; rev:14; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious services.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,145c06300d61b3a0ce2c944fe7cdcb96

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016701
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious smss.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/smss.exe"; http_uri; nocase; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; reference:md5,450dbe96d7f4108474071aca5826fc43; classtype:bad-unknown; sid:2016701; rev:13; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious smss.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,450dbe96d7f4108474071aca5826fc43

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 14

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016702
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious csrss.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/csrss.exe"; http_uri; nocase; fast_pattern; isdataat:!1,relative; metadata: former_category INFO; reference:md5,21a069667a6dba38f06765e414e48824; classtype:bad-unknown; sid:2016702; rev:13; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious csrss.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,21a069667a6dba38f06765e414e48824

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 14

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016703
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious rundll32.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/rundll32.exe"; http_uri; nocase; fast_pattern; isdataat:!1,relative; metadata: former_category INFO; reference:md5,ea3dec87f79ff97512c637a5c8868a7e; classtype:bad-unknown; sid:2016703; rev:13; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious rundll32.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,ea3dec87f79ff97512c637a5c8868a7e

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 14

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016699
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious lsass.exe in URI"; flow:established,to_server; content:"GET"; http_method; urilen:<100; content:"/lsass.exe"; http_uri; nocase; isdataat:!1,relative; fast_pattern; metadata: former_category INFO; reference:md5,d929747212309559cb702dd062fb3e5d; classtype:bad-unknown; sid:2016699; rev:14; metadata:created_at 2013_04_01, updated_at 2019_09_28;)
` 

Name : **Suspicious lsass.exe in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,d929747212309559cb702dd062fb3e5d

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-09-28

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016580
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Java Request to DynDNS Pro Dynamic DNS Domain"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/\.(?:i(?:s(?:-(?:a(?:-(?:(?:(?:h(?:ard-work|unt)e|financialadviso)r|d(?:e(?:mocrat|signer)|octor)|t(?:e(?:acher|chie)|herapist)|r(?:epublican|ockstar)|n(?:ascarfan|urse)|anarchist|musician)\.com|c(?:(?:(?:ubicle-sla|onservati)ve|pa)\.com|a(?:ndidate\.org|terer\.com)|hef\.(?:com|net|org)|elticsfan\.org)|l(?:i(?:ber(?:tarian|al)\.com|nux-user\.org)|(?:a(?:ndscap|wy)er|lama)\.com)|p(?:(?:ersonaltrain|hotograph|lay)er\.com|a(?:inter\.com|tsfan\.org))|b(?:(?:(?:ookkeep|logg)er|ulls-fan)\.com|ruinsfan\.org)|s(?:o(?:cialist\.com|xfan\.org)|tudent\.com)|g(?:eek\.(?:com|net|org)|(?:reen|uru)\.com)|knight\.org)|n-(?:a(?:c(?:t(?:ress|or)|countant)|(?:narch|rt)ist)|en(?:tertain|gine)er)\.com)|(?:into-(?:(?:car(?:toon)?|game)s|anime)|(?:(?:not-)?certifie|with-theban)d|uberleet|gone)\.com|(?:very-(?:(?:goo|ba)d|sweet|evil|nice)|found)\.org|s(?:aved\.org|lick\.com)|l(?:eet\.com|ost\.org)|by\.us)|a-(?:geek\.(?:com|net|org)|hockeynut\.com)|t(?:eingeek|mein)\.de|smarterthanyou\.com)|n-the-band\.net|amallama\.com)|f(?:rom-(?:(?:i[adln]|w[aivy]|o[hkr]|[hr]i|d[ce]|k[sy]|p[ar]|s[cd]|t[nx]|v[at]|fl|ga|ut)\.com|m(?:[adinost]\.com|e\.org)|n(?:[cdehjmv]\.com|y\.net)|a(?:[klr]\.com|z\.net)|c(?:[at]\.com|o\.net)|la\.net)|or(?:-(?:(?:(?:mor|som|th)e|better)\.biz|our\.info)|got\.h(?:er|is)\.name)|uettertdasnetz\.de|tpaccess\.cc)|s(?:e(?:l(?:ls(?:-(?:for-(?:less|u)\.com|it\.net)|yourhome\.org)|fip\.(?:info|biz|com|net|org))|rve(?:bbs\.(?:com|net|org)|ftp\.(?:net|org)|game\.org))|(?:aves-the-whales|pace-to-rent|imple-url)\.com|crapp(?:er-site\.net|ing\.cc)|tuff-4-sale\.(?:org|us)|hacknet\.nu)|d(?:o(?:es(?:ntexist\.(?:com|org)|-it\.net)|ntexist\.(?:com|net|org)|omdns\.(?:com|org))|yn(?:a(?:lias\.(?:com|net|org)|thome\.net)|-o-saur\.com|dns\.ws)|ns(?:alias\.(?:com|net|org)|dojo\.(?:com|net|org))|vrdns\.org)|h(?:o(?:me(?:linux\.(?:com|net|org)|unix\.(?:com|net|org)|(?:\.dyn)?dns\.org|ftp\.(?:net|org)|ip\.net)|bby-site\.(?:com|org))|ere-for-more\.info|am-radio-op\.net)|b(?:log(?:dns\.(?:com|net|org)|site\.org)|(?:uyshouses|roke-it)\.net|arrel?l-of-knowledge\.info|oldlygoingnowhere\.org|etter-than\.tv)|g(?:o(?:tdns\.(?:com|org)|\.dyndns\.org)|ame-(?:server\.cc|host\.org)|et(?:myip\.com|s-it\.net)|roks-th(?:is|e)\.info)|e(?:st-(?:(?:a-la-ma(?:is|si)|le-patr)on|mon-blogueur)\.com|ndof(?:internet\.(?:net|org)|theinternet\.org))|l(?:e(?:btimnetz|itungsen)\.de|ikes(?:candy|-pie)\.com|and-4-sale\.us)|m(?:i(?:sconfused\.org|ne\.nu)|yp(?:hotos\.cc|ets\.ws)|erseine\.nu)|w(?:ebhop\.(?:info|biz|net|org)|ritesthisblog\.com|orse-than\.tv)|t(?:eaches-yoga\.com|raeumtgerade\.de|hruhere\.net)|k(?:icks-ass\.(?:net|org)|nowsitall\.info)|o(?:ffice-on-the\.net|n-the-web\.tv)|(?:neat-url|cechire)\.com|podzone\.(?:net|org)|at-band-camp\.net|readmyblog\.org)(\x3a\d{1,5})?$/W"; classtype:bad-unknown; sid:2016580; rev:4; metadata:created_at 2013_03_15, updated_at 2019_09_09;)
` 

Name : **Java Request to DynDNS Pro Dynamic DNS Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-15

Last modified date : 2019-09-09

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016583
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Java Request to DNSDynamic Dynamic DNS Domain"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/\.(?:d(?:ns(?:d(?:ynamic\.(?:com|net)|\.(?:info|me))|api\.info|get\.org|53\.biz)|dns01\.com)|(?:f(?:lashserv|e100|tp21)|adultdns|mysq1|wow64)\.net|(?:(?:ima|voi)p01|(?:user|ole)32|kadm5)\.com|t(?:tl60\.(?:com|org)|empors\.com|ftpd\.net)|s(?:sh(?:01\.com|22\.net)|ql01\.com)|http(?:(?:s443|01)\.com|80\.info)|n(?:s360\.info|tdll\.net)|x(?:ns01\.com|64\.me)|craftx\.biz)(\x3a\d{1,5})?$/W"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2016583; rev:5; metadata:created_at 2013_03_15, updated_at 2019_09_09;)
` 

Name : **SUSPICIOUS Java Request to DNSDynamic Dynamic DNS Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-15

Last modified date : 2019-09-09

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024470
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP POST to Free Webhost - Possible Successful Phish (site40 . net) Jul 18 2017"; flow:to_server,established; content:"POST"; http_method; content:"site40.net|0d 0a|"; http_header; fast_pattern; metadata: former_category INFO; classtype:trojan-activity; sid:2024470; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2017_07_17, updated_at 2019_09_26;)
` 

Name : **HTTP POST to Free Webhost - Possible Successful Phish (site40 . net) Jul 18 2017** 

Attack target : Client_Endpoint

Description : Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-07-17

Last modified date : 2019-09-26

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017515
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET INFO User-Agent (python-requests) Inbound to Webserver"; flow:established,to_server; content:"python-requests/"; http_user_agent; classtype:attempted-recon; sid:2017515; rev:5; metadata:created_at 2013_09_25, updated_at 2019_09_27;)
` 

Name : **User-Agent (python-requests) Inbound to Webserver** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-09-25

Last modified date : 2019-09-27

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013438
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.uni.cc domain"; flow:to_server,established; content:".uni.cc|0D 0A|"; http_header; classtype:bad-unknown; sid:2013438; rev:4; metadata:created_at 2011_08_19, updated_at 2019_09_27;)
` 

Name : **HTTP Request to a *.uni.cc domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-19

Last modified date : 2019-09-27

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011865
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Embedded Executable File in PDF - This Program Cannot Be Run in DOS Mode"; flow:established,to_client; flowbits:isset,ET.pdf.in.http; file_data; content:"This program cannot be run in DOS mode"; nocase; classtype:bad-unknown; sid:2011865; rev:7; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2010_10_29, updated_at 2019_09_27;)
` 

Name : **Embedded Executable File in PDF - This Program Cannot Be Run in DOS Mode** 

Attack target : Client_Endpoint

Description : This signature detects the download via HTTP of a PDF that has an embedded executable.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-10-29

Last modified date : 2019-09-27

Rev version : 7

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025275
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Windows OS Submitting USB Metadata to Microsoft"; flow:established,to_server; content:"POST"; http_method; content:"metadata.svc"; http_uri; isdataat:!1,relative; content:"/DeviceMetadataService/GetDeviceMetadata|22 0d 0a|"; http_header; content:"MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT"; http_user_agent; depth:42; isdataat:!1,relative; fast_pattern; threshold:type limit, seconds 300, count 1, track by_src; metadata: former_category INFO; classtype:misc-activity; sid:2025275; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_01_31, performance_impact Low, updated_at 2019_09_30;)
` 

Name : **Windows OS Submitting USB Metadata to Microsoft** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-01-31

Last modified date : 2019-09-30

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2003614
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO WinUpack Modified PE Header Inbound"; flow:established; content:"|4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00|"; fast_pattern; reference:url,doc.emergingthreats.net/bin/view/Main/WinPEHeaders; classtype:bad-unknown; sid:2003614; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **WinUpack Modified PE Header Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/WinPEHeaders

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003615
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO WinUpack Modified PE Header Outbound"; flow:established; content:"|4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00|"; fast_pattern; reference:url,doc.emergingthreats.net/bin/view/Main/WinPEHeaders; classtype:bad-unknown; sid:2003615; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **WinUpack Modified PE Header Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/WinPEHeaders

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015674
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO 3XX redirect to data URL"; flow:from_server,established; content:"3"; depth:1; http_stat_code; content:"Location|3a 20|data|3a|"; fast_pattern; http_header; classtype:misc-activity; sid:2015674; rev:4; metadata:created_at 2012_09_04, updated_at 2019_10_07;)
` 

Name : **3XX redirect to data URL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-04

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015675
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SimpleTDS go.php (sid)"; flow:established,to_server; content:"/go.php?sid="; http_uri; fast_pattern; classtype:trojan-activity; sid:2015675; rev:4; metadata:created_at 2012_09_04, updated_at 2019_10_07;)
` 

Name : **SimpleTDS go.php (sid)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-04

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015822
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 9 User-Agent"; flow:established,to_server; content:"Windows NT 9"; nocase; http_user_agent; fast_pattern; classtype:trojan-activity; sid:2015822; rev:4; metadata:created_at 2012_10_19, updated_at 2019_10_07;)
` 

Name : **Suspicious Windows NT version 9 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-19

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015899
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 2 User-Agent"; flow: established,to_server; content:"Windows NT 2"; nocase; http_user_agent; fast_pattern; classtype:trojan-activity; sid:2015899; rev:4; metadata:created_at 2012_11_19, updated_at 2019_10_07;)
` 

Name : **Suspicious Windows NT version 2 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-19

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015900
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 3 User-Agent"; flow: established,to_server; content:"Windows NT 3"; nocase; http_user_agent; fast_pattern; classtype:trojan-activity; sid:2015900; rev:5; metadata:created_at 2012_11_19, updated_at 2019_10_07;)
` 

Name : **Suspicious Windows NT version 3 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-19

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015965
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE SCardForgetReaderGroupA (Used in Malware Anti-Debugging)"; flow:established,to_client; file_data; flowbits:isset,ET.http.binary; content:"SCardForgetReaderGroupA"; fast_pattern; reference:url,www.trusteer.com/blog/evading-malware-researchers-shylock%E2%80%99s-new-trick; classtype:misc-activity; sid:2015965; rev:5; metadata:created_at 2012_11_29, updated_at 2019_10_07;)
` 

Name : **EXE SCardForgetReaderGroupA (Used in Malware Anti-Debugging)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.trusteer.com/blog/evading-malware-researchers-shylock%E2%80%99s-new-trick

CVE reference : Not defined

Creation date : 2012-11-29

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016302
`alert udp $HOME_NET 1900 -> any any (msg:"ET INFO UPnP Discovery Search Response vulnerable UPnP device 1"; content:"miniupnpd/1."; fast_pattern; pcre:"/^Server\x3a[^\r\n]*miniupnpd\/1\.[0-3]/mi"; reference:url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play; reference:url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf; reference:cve,2013-0229; classtype:successful-recon-limited; sid:2016302; rev:6; metadata:created_at 2013_01_29, updated_at 2019_10_07;)
` 

Name : **UPnP Discovery Search Response vulnerable UPnP device 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,community.rapid7.com/community/infosec/blog/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play|url,upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf|cve,2013-0229

CVE reference : Not defined

Creation date : 2013-01-29

Last modified date : 2019-10-07

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016510
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Serialized Java Applet (Used by some EKs in the Wild)"; flow:established,from_server; file_data; content:"<embed"; nocase; content:"object"; distance:0; nocase; pcre:"/^[\r\n\s]*=[\r\n\s]*[\x22\x27][^\x22\x27]+\.ser[\x22\x27]/Ri"; content:"application/x-java-"; fast_pattern; metadata: former_category INFO; classtype:trojan-activity; sid:2016510; rev:5; metadata:created_at 2013_02_26, updated_at 2019_10_07;)
` 

Name : **Serialized Java Applet (Used by some EKs in the Wild)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-26

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016765
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO PDF - Acrobat Enumeration - pdfobject.js"; flow:established,to_server; content:"/pdfobject.js"; http_uri; fast_pattern; classtype:misc-activity; sid:2016765; rev:3; metadata:created_at 2013_04_17, updated_at 2019_10_07;)
` 

Name : **PDF - Acrobat Enumeration - pdfobject.js** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-17

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016802
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO myobfuscate.com Encoded Script Calling home"; flow:to_server,established; content:"/?getsrc="; http_uri; content:"&url="; http_uri; content:"api.myobfuscate.com|0d|"; http_header; nocase; fast_pattern; classtype:misc-activity; sid:2016802; rev:5; metadata:created_at 2013_04_30, updated_at 2019_10_07;)
` 

Name : **myobfuscate.com Encoded Script Calling home** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-30

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016847
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible Chrome Plugin install"; flow:to_server,established; content:"|2f|crx|2f|blobs"; http_uri; nocase; fast_pattern; content:" Chrome/"; http_user_agent; reference:url,blogs.technet.com/b/mmpc/archive/2013/05/10/browser-extension-hijacks-facebook-profiles.aspx; classtype:bad-unknown; sid:2016847; rev:4; metadata:created_at 2013_05_14, updated_at 2019_10_07;)
` 

Name : **Possible Chrome Plugin install** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.technet.com/b/mmpc/archive/2013/05/10/browser-extension-hijacks-facebook-profiles.aspx

CVE reference : Not defined

Creation date : 2013-05-14

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016846
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible Firefox Plugin install"; flow:to_server,established; content:".xpi"; http_uri; nocase; fast_pattern; pcre:"/\.xpi$/Ui"; content:" Firefox/"; http_user_agent; reference:url,research.zscaler.com/2012/09/how-to-install-silently-malicious.html; classtype:bad-unknown; sid:2016846; rev:5; metadata:created_at 2013_05_14, updated_at 2019_10_07;)
` 

Name : **Possible Firefox Plugin install** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,research.zscaler.com/2012/09/how-to-install-silently-malicious.html

CVE reference : Not defined

Creation date : 2013-05-14

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017968
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Possible Process Dump in POST body"; flow:established,to_server; content:"POST"; http_method; content:"System Idle Process"; fast_pattern; http_client_body; metadata: former_category INFO; reference:url,www.securelist.com/en/blog/208214213/The_Icefog_APT_Hits_US_Targets_With_Java_Backdoor; classtype:trojan-activity; sid:2017968; rev:5; metadata:created_at 2014_01_14, updated_at 2019_10_07;)
` 

Name : **Suspicious Possible Process Dump in POST body** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.securelist.com/en/blog/208214213/The_Icefog_APT_Hits_US_Targets_With_Java_Backdoor

CVE reference : Not defined

Creation date : 2014-01-14

Last modified date : 2019-10-07

Rev version : 5

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018211
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Adultdns.net"; flow:established,to_server; content:".adultdns.net"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2Eadultdns\x2Enet/H"; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018211; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain Adultdns.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018212
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Servehttp.com"; flow:established,to_server; content:".servehttp.com"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2Eservehttp.com/H"; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018212; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain Servehttp.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018214
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Redirectme.net"; flow:established,to_server; content:".redirectme.net"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2Eredirectme\x2Enet/H"; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018214; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain Redirectme.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018215
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain Zapto.org"; flow:established,to_server; content:".zapto.org"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2Ezapto\x2Eorg/H"; reference:url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/; reference:url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/; classtype:bad-unknown; sid:2018215; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain Zapto.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blogs.cisco.com/security/dynamic-detection-of-malicious-ddns/|url,labs.umbrella.com/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018217
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain serveblog.net"; flow:established,to_server; content:".serveblog.net"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2serveblog\x2Enet/H"; reference:url,isc.sans.edu/diary/Fiesta!/17739; classtype:bad-unknown; sid:2018217; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain serveblog.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,isc.sans.edu/diary/Fiesta!/17739

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018218
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Connection To DDNS Domain myftp.com"; flow:established,to_server; content:".myftp.com"; http_header; nocase; fast_pattern; pcre:"/Host\x3A[^\r\n]*\x2myftp\x2Ecom/H"; reference:url,isc.sans.edu/diary/Fiesta!/17739; classtype:bad-unknown; sid:2018218; rev:3; metadata:created_at 2014_03_04, updated_at 2019_10_07;)
` 

Name : **HTTP Connection To DDNS Domain myftp.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,isc.sans.edu/diary/Fiesta!/17739

CVE reference : Not defined

Creation date : 2014-03-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015821
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Windows NT version 8 User-Agent"; flow: established,to_server; content:"Windows NT 8"; nocase; http_user_agent; fast_pattern; content:!"NOKIA"; nocase; http_user_agent; classtype:trojan-activity; sid:2015821; rev:5; metadata:created_at 2012_10_19, updated_at 2019_10_07;)
` 

Name : **Suspicious Windows NT version 8 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-19

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018365
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.mrbasic.com Domain"; flow:established,to_server; content:".mrbasic.com"; http_header; nocase; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.mrbasic\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018365; rev:3; metadata:created_at 2014_04_04, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to a *.mrbasic.com Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-04-04

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018809
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.passinggas.net Domain (Sitelutions)"; flow:established,to_server; content:".passinggas.net"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.passinggas\.net(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018809; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.passinggas.net Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018811
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.myredirect.us Domain (Sitelutions)"; flow:established,to_server; content:".myredirect.us"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.myredirect\.us(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018811; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.myredirect.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018813
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.rr.nu Domain (Sitelutions)"; flow:established,to_server; content:".rr.nu"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.rr\.nu(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018813; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.rr.nu Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018815
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.kwik.to Domain (Sitelutions)"; flow:established,to_server; content:".kwik.to"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.kwik\.to(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018815; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.kwik.to Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018817
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.myfw.us Domain (Sitelutions)"; flow:established,to_server; content:".myfw.us"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.myfw\.us(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018817; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.myfw.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018819
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.ontheweb.nu Domain (Sitelutions)"; flow:established,to_server; content:".ontheweb.nu"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.ontheweb\.nu(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018819; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.ontheweb.nu Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018821
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.isthebe.st Domain (Sitelutions)"; flow:established,to_server; content:".isthebe.st"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.isthebe\.st(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018821; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.isthebe.st Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018823
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.byinter.net Domain (Sitelutions)"; flow:established,to_server; content:".byinter.net"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.byinter\.net(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018823; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.byinter.net Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018825
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.findhere.org Domain (Sitelutions)"; flow:established,to_server; content:".findhere.org"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.findhere\.org(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018825; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.findhere.org Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018827
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.onthenetas.com Domain (Sitelutions)"; flow:established,to_server; content:".onthenetas.com"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.onthenetas\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018827; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.onthenetas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018829
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.uglyas.com Domain (Sitelutions)"; flow:established,to_server; content:".uglyas.com"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.uglyas\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018829; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.uglyas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018831
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.assexyas.com Domain (Sitelutions)"; flow:established,to_server; content:".assexyas.com"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.assexyas\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018831; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.assexyas.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018833
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.passas.us Domain (Sitelutions)"; flow:established,to_server; content:".passas.us"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.passas\.us(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018833; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.passas.us Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018835
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.athissite.com Domain (Sitelutions)"; flow:established,to_server; content:".athissite.com"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.athissite\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018835; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.athissite.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018837
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.athersite.com Domain (Sitelutions)"; flow:established,to_server; content:".athersite.com"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.athersite\.com(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018837; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.athersite.com Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018839
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.isgre.at Domain (Sitelutions)"; flow:established,to_server; content:".isgre.at"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.isgre\.at(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018839; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.isgre.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018841
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.lookin.at Domain (Sitelutions)"; flow:established,to_server; content:".lookin.at"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.lookin\.at(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018841; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.lookin.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018843
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.bestdeals.at Domain (Sitelutions)"; flow:established,to_server; content:".bestdeals.at"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.bestdeals\.at(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018843; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.bestdeals.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018845
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to *.lowestprices.at Domain (Sitelutions)"; flow:established,to_server; content:".lowestprices.at"; nocase; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.lowestprices\.at(?:\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2018845; rev:3; metadata:created_at 2014_07_30, updated_at 2019_10_07;)
` 

Name : **DYNAMIC_DNS HTTP Request to *.lowestprices.at Domain (Sitelutions)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-07-30

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013378
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.de.ms domain"; flow:to_server,established; content:".de.ms|0d 0a|"; fast_pattern; http_header; classtype:bad-unknown; sid:2013378; rev:4; metadata:created_at 2011_08_08, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.de.ms domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-08

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013828
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.eu.tf domain"; flow: to_server,established; content:".eu.tf|0D 0A|"; fast_pattern; http_header; classtype:bad-unknown; sid:2013828; rev:4; metadata:created_at 2011_11_04, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.eu.tf domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-04

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013969
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a .noip.cn domain"; flow:to_server,established; content:".noip.cn|0D 0A|"; fast_pattern; http_header; classtype:bad-unknown; sid:2013969; rev:4; metadata:created_at 2011_11_28, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a .noip.cn domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-28

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015551
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO HTTP Request to a *.upas.su domain"; flow:to_server,established; content:".upas.su|0d 0a|"; fast_pattern; http_header; classtype:bad-unknown; sid:2015551; rev:4; metadata:created_at 2012_07_31, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.upas.su domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-31

Last modified date : 2019-10-07

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020888
`alert tls $HOME_NET any -> 195.22.26.192/26 443 (msg:"ET INFO invalid.cab domain in SNI"; flow:established,to_server; content:"|0b|invalid.cab"; fast_pattern; flowbits:set,ET.invalid.cab; flowbits:noalert; classtype:misc-activity; sid:2020888; rev:3; metadata:created_at 2015_04_10, updated_at 2019_10_07;)
` 

Name : **invalid.cab domain in SNI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-04-10

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021067
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M1 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|1"; http_header; fast_pattern; pcre:"/^Host\x3a\x201\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021067; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M1 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021068
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M2 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|2"; http_header; fast_pattern; pcre:"/^Host\x3a\x202\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021068; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M2 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021069
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M3 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|3"; http_header; fast_pattern; pcre:"/^Host\x3a\x203\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021069; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M3 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021070
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M4 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|4"; http_header; fast_pattern; pcre:"/^Host\x3a\x204\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021070; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M4 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021071
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M5 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|5"; http_header; fast_pattern; pcre:"/^Host\x3a\x205\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021071; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M5 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021072
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M6 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|6"; http_header; fast_pattern; pcre:"/^Host\x3a\x206\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021072; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M6 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021073
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M7 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|7"; http_header; fast_pattern; pcre:"/^Host\x3a\x207\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021073; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M7 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021074
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M8 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|8"; http_header; fast_pattern; pcre:"/^Host\x3a\x208\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021074; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M8 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021075
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host M9 (noalert)"; flowbits:set,http.dottedquadhost; flowbits:noalert; flow:to_server,established; content:"Host|3a 20|9"; http_header; fast_pattern; pcre:"/^Host\x3a\x209\d{0,1}\.\d{1,3}\.\d{1,3}\.\d{1,3}\r$/Hm"; classtype:bad-unknown; sid:2021075; rev:3; metadata:created_at 2015_05_07, updated_at 2019_10_07;)
` 

Name : **Dotted Quad Host M9 (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-05-07

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022080
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO form-data flowbit set (noalert)"; flow:to_server,established; dsize:>0; content:"Content-Type|3a 20|multipart|2f|form-data"; fast_pattern; flowbits:set,ET.formdata; flowbits:noalert; classtype:not-suspicious; sid:2022080; rev:2; metadata:created_at 2015_11_12, updated_at 2019_10_07;)
` 

Name : **form-data flowbit set (noalert)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-12

Last modified date : 2019-10-07

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022264
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible MSXMLHTTP Request (exe) unset (no exe)"; flow:to_server,established; flowbits:isset,et.MS.XMLHTTP.no.exe.request; content:".exe"; nocase; http_uri; fast_pattern; flowbits:unset,et.MS.XMLHTTP.no.exe.request; flowbits:noalert; classtype:misc-activity; sid:2022264; rev:5; metadata:created_at 2015_12_15, updated_at 2019_10_07;)
` 

Name : **Possible MSXMLHTTP Request (exe) unset (no exe)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-15

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022265
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible MSXMLHTTP Request (msi) unset (no exe)"; flow:to_server,established; flowbits:isset,et.MS.XMLHTTP.no.exe.request; content:".msi"; nocase; http_uri; fast_pattern; flowbits:unset,et.MS.XMLHTTP.no.exe.request; flowbits:noalert; classtype:misc-activity; sid:2022265; rev:5; metadata:created_at 2015_12_15, updated_at 2019_10_07;)
` 

Name : **Possible MSXMLHTTP Request (msi) unset (no exe)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-15

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022266
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible MSXMLHTTP Request (msp) unset (no exe)"; flow:to_server,established; flowbits:isset,et.MS.XMLHTTP.no.exe.request; content:".msp"; nocase; http_uri; fast_pattern; flowbits:unset,et.MS.XMLHTTP.no.exe.request; flowbits:noalert; classtype:misc-activity; sid:2022266; rev:5; metadata:created_at 2015_12_15, updated_at 2019_10_07;)
` 

Name : **Possible MSXMLHTTP Request (msp) unset (no exe)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-15

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014472
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAVA - Java Archive Download"; flow:from_server,established; flowbits:isnotset,ET.http.javaclient.vulnerable; flowbits:isset,ET.http.javaclient; file_data; content:"PK"; within:2; content:".class"; nocase; fast_pattern; classtype:trojan-activity; sid:2014472; rev:8; metadata:created_at 2012_04_04, updated_at 2019_10_07;)
` 

Name : **JAVA - Java Archive Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-04

Last modified date : 2019-10-07

Rev version : 8

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022636
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO SUSPICIOUS Single JS file inside of ZIP Download (Observed as lure in malspam campaigns)"; flow:established,to_client; file_data; content:"PK"; within:2; content:"PK|01 02|"; distance:0; pcre:"/^.{42}[\x20-\x7f]{1,500}\.jsPK\x05\x06.{4}\x01\x00\x01\x00/Rsi"; content:".jsPK|05 06|"; nocase; fast_pattern; metadata: former_category INFO; classtype:misc-activity; sid:2022636; rev:4; metadata:created_at 2016_03_22, updated_at 2019_10_07;)
` 

Name : **SUSPICIOUS Single JS file inside of ZIP Download (Observed as lure in malspam campaigns)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-03-22

Last modified date : 2019-10-07

Rev version : 4

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022914
`alert udp any any -> $HOME_NET 137 (msg:"ET INFO NBNS Name Query Response Possible WPAD Spoof BadTunnel"; byte_test:1,&,0x80,2; byte_test:1,!&,0x40,2; byte_test:1,!&,0x20,2; byte_test:1,!&,0x10,2; byte_test:1,=,0x00,3; content:"|00 00|"; offset:4; depth:2; content:"|46 48 46 41 45 42 45|"; fast_pattern; reference:url,tools.ietf.org/html/draft-ietf-wrec-wpad-01; reference:url,ietf.org/rfc/rfc1002.txt; classtype:protocol-command-decode; sid:2022914; rev:2; metadata:created_at 2016_06_23, updated_at 2019_10_07;)
` 

Name : **NBNS Name Query Response Possible WPAD Spoof BadTunnel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,tools.ietf.org/html/draft-ietf-wrec-wpad-01|url,ietf.org/rfc/rfc1002.txt

CVE reference : Not defined

Creation date : 2016-06-23

Last modified date : 2019-10-07

Rev version : 2

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023629
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Suspicious Empty SSL Certificate - Observed in Cobalt Strike"; flow:from_server,established; content:"|55 04 06 13 00|"; fast_pattern; content:"|16|"; content:"|02|"; distance:0; within:8; content:"|55 04 06|"; distance:0; content:"|00|"; distance:1; within:2; content:"|55 04 08|"; distance:0; content:"|00|"; distance:1; within:2; content:"|55 04 07|"; distance:0; content:"|00|"; distance:1; within:2; content:"|55 04 0a|"; distance:0; content:"|00|"; distance:1; within:2; content:"|55 04 0b|"; distance:0; content:"|00|"; distance:1; within:2; content:"|55 04 03|"; distance:0; content:"|00|"; distance:1; within:2; metadata: former_category INFO; classtype:trojan-activity; sid:2023629; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2016_10_24, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Suspicious Empty SSL Certificate - Observed in Cobalt Strike** 

Attack target : Client_Endpoint

Description : Alerts are generated when a certificate is observed on the wire with all empty fields.

Tags : Not defined

Affected products : Any

Alert Classtype : targeted-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-10-24

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023454
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.science) - set"; flow:established,to_server; content:".science|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.science(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023454; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.science) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023455
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.top) - set"; flow:established,to_server; content:".top|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.top(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023455; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.top) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023456
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.stream) - set"; flow:established,to_server; content:".stream|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.stream(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023456; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.stream) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023457
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.download) - set"; flow:established,to_server; content:".download|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.download(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023457; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.download) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023459
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.biz) - set"; flow:established,to_server; content:".biz|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.biz(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023459; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.biz) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023460
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.accountant) - set"; flow:established,to_server; content:".accountant|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.accountant(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023460; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.accountant) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023461
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.click) - set"; flow:established,to_server; content:".click|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.click(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023461; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.click) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023462
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.link) - set"; flow:established,to_server; content:".link|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.link(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023462; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.link) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023463
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.win) - set"; flow:established,to_server; content:".win|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.win(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2023463; rev:3; metadata:affected_product Any, attack_target Client_and_Server, signature_severity Minor, created_at 2016_10_27, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.win) - set** 

Attack target : Client_and_Server

Description : Alerts on possible EXE downloads to suspicious TLDs. This does not necessarily indicate malicious activity has occurred but may warrant a closer look as it is very common for these TLDs to host malicious payloads.

Tags : Not defined

Affected products : Any

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2016-10-27

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015708
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO - Applet Tag In Edwards Packed JavaScript"; flow:established,to_client; file_data; content:"eval(function(p,a,c"; content:"|7C|applet|7C|"; nocase; fast_pattern; content:!"|7C|_dynarch_popupCalendar|7C|"; classtype:bad-unknown; sid:2015708; rev:6; metadata:created_at 2012_09_17, updated_at 2019_10_07;)
` 

Name : **- Applet Tag In Edwards Packed JavaScript** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-17

Last modified date : 2019-10-07

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023749
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Lock Emoji In Title - Possible Social Engineering Attempt"; flow:from_server,established; file_data; content:"<title>"; nocase; pcre:"/^(?:(?!<\/title).)*\x26\x23x1F512/Ri"; content:"|26 23|x1F512"; fast_pattern; classtype:trojan-activity; sid:2023749; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2017_01_19, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Lock Emoji In Title - Possible Social Engineering Attempt** 

Attack target : Client_Endpoint

Description : In an attempt to trick an end user into thinking they are visiting a https secured website, some phishing pages are displaying a lock emoji within the title. 

Emerging Threats phishing signatures are designed to alert analysts to users who may have fallen victim to social engineering by entering their credentials into a fraudulent website.

Typically scammers will attempt to steal a victim’s account credentials through the use of a fake login page. In the attack, the actor crafts a fake login page and hosts it on a server they control. This server may be owned by the actor through compromise or it may be a typo squatted or fraudulent domain. The phisher will then embed the URL for this page or an HTML/PDF attachment with the URL in a phishing email. The email can be sent as part of a broad-based or highly targeted campaign, and typically uses a templated lure. Clicking the link will lead the user to a fake page that typically carries graphics and branding very similar to those of the legitimate account login page.

When the user enters their credentials in the fraudulent login page, attackers have several options for retrieving them:

(a) Emailed off with a PHP mail() function to some attacker controlled email address
(b) Posted to an external site
(c) Be stored in a text file on the same server where the phish lives, to be retrieved manually later

Of these options, the most commonly observed is (a), while method (c) is the least commonly observed. Cases have also been observed where phishing kits (that is, software that generates the phish) or services are sold or given away on forums, and these kits may have backdoors or may also mail off the stolen credentials to the creator of the phishing kit.

The user is frequently redirected to the real login page: to the victim, it will simply appear that their login failed to process and they will often attempt to login again. Alternatively a document or PDF may be shown to the user. 

Emerging Threats phishing signatures typically fall into a few categories. The first is the “landing page” signature. This indicates that a user has clicked on a link in an email and visited a webpage containing characteristics of known phishing templates. This is typically of low value to an analyst as there is typically no loss of information at this point. The second is the “success” signature which indicates that a user has given away their credentials. This is typically of high value to an analyst as there is evidence that credentials have been lost. The third category of phishing signatures involve methods that have been observed to be unique to a majority of phishing scams. This includes things such as redirects, notes left by authors, and common obfuscation methods. A whitepaper concerning modern phishing obfuscation methods can be found at https://www.proofpoint.com/us/threat-insight/post/Obfuscation-Techniques-In-Phishing-Attacks


Tags : Phishing

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-01-19

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2022271
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS Possible Evil Download wsf Double Ext No Referer"; flow:established,to_server; content:"GET"; http_method; content:!"User-Agent|3a 20 2a|"; http_header; content:".wsf"; http_uri; nocase; fast_pattern; pcre:"/\/[^\x2f]+\.[^\x2f]+\.wsf$/Ui"; metadata: former_category INFO; classtype:trojan-activity; sid:2022271; rev:4; metadata:created_at 2015_12_17, updated_at 2019_10_07;)
` 

Name : **SUSPICIOUS Possible Evil Download wsf Double Ext No Referer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-12-17

Last modified date : 2019-10-07

Rev version : 4

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024236
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET INFO SMTP PDF Attachment Flowbit Set"; flow:established,from_server; content:"|0d 0a 0d 0a|JVBERi"; fast_pattern; flowbits:set,ET.pdf.in.smtp.attachment; flowbits:noalert; metadata: former_category INFO; classtype:bad-unknown; sid:2024236; rev:3; metadata:attack_target SMTP_Server, deployment Perimeter, signature_severity Informational, created_at 2017_04_21, updated_at 2019_10_07;)
` 

Name : **SMTP PDF Attachment Flowbit Set** 

Attack target : SMTP_Server

Description : This rule simply sets a flowbit for a PDF header in SMTP attachment (base64). 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-04-21

Last modified date : 2019-10-07

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018174
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO RelevantKnowledge Adware CnC Beacon"; flow:established,to_server; content:"GET"; http_method; content:"X-OSSProxy|3a|"; fast_pattern; http_header; content:"&os="; http_uri; content:"&osmajorver="; http_uri; distance:0; content:"&osminorver="; http_uri; distance:0; content:"&osmajorsp="; http_uri; distance:0; content:"&lang="; http_uri; distance:0; content:"&country="; http_uri; distance:0; content:"&ossname="; http_uri; distance:0; content:"&brand="; http_uri; distance:0; content:"&bits="; http_uri; distance:0; metadata: former_category INFO; reference:md5,d93b888e08693119a1b0dd3983b8d1ec; classtype:trojan-activity; sid:2018174; rev:5; metadata:created_at 2014_02_25, updated_at 2019_10_07;)
` 

Name : **RelevantKnowledge Adware CnC Beacon** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : md5,d93b888e08693119a1b0dd3983b8d1ec

CVE reference : Not defined

Creation date : 2014-02-25

Last modified date : 2019-10-07

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025495
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.men) - set"; flow:established,to_server; content:".men|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.men(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025495; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.men) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025497
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.webcam) - set"; flow:established,to_server; content:".webcam|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.webcam(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025497; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.webcam) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025498
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.yokohama) - set"; flow:established,to_server; content:".yokohama|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.yokohama(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025498; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.yokohama) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025499
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.tokyo) - set"; flow:established,to_server; content:".tokyo|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.tokyo(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025499; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.tokyo) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025500
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.gq) - set"; flow:established,to_server; content:".gq|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.gq(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category HUNTING; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025500; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.gq) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025501
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible EXE Download From Suspicious TLD (.work) - set"; flow:established,to_server; content:".work|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a[^\r\n]+\.work(?:\x3a\d{1,5})?\r?$/Hmi"; flowbits:set,ET.SuspExeTLDs; flowbits:noalert; metadata: former_category INFO; reference:url,www.spamhaus.org/statistics/tlds/; classtype:misc-activity; sid:2025501; rev:3; metadata:created_at 2018_04_16, updated_at 2019_10_07;)
` 

Name : **Possible EXE Download From Suspicious TLD (.work) - set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2018-04-16

Last modified date : 2019-10-07

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014954
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Vulnerable iTunes Version 10.6.x"; flow:established,to_server; content:"iTunes/10.6."; http_user_agent; depth:12;  pcre:"/^User-Agent\x3a\x20iTunes\/10\.6\.[0-1]/Hm"; flowbits:set,ET.iTunes.vuln; flowbits:noalert; classtype:policy-violation; sid:2014954; rev:10; metadata:created_at 2012_06_25, updated_at 2019_10_11;)
` 

Name : **Vulnerable iTunes Version 10.6.x** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-06-25

Last modified date : 2019-10-11

Rev version : 10

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003530
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Mozilla User-Agent Separator - likely Fake (Mozilla/4.0+(compatible +MSIE+)"; flow:to_server,established; content:"Mozilla/4.0+(compatible|3b|+MSIE+/"; http_user_agent; depth:31; fast_pattern; metadata: former_category INFO; reference:url,doc.emergingthreats.net/2003530; classtype:trojan-activity; sid:2003530; rev:15; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious Mozilla User-Agent Separator - likely Fake (Mozilla/4.0+(compatible +MSIE+)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2003530

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 15

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016695
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO SUSPICIOUS UA starting with Mozilla/0"; flow:established,to_server; content:"Mozilla/0"; fast_pattern; nocase; http_user_agent; depth:9; classtype:bad-unknown; sid:2016695; rev:3; metadata:created_at 2013_04_01, updated_at 2019_10_15;)
` 

Name : **SUSPICIOUS UA starting with Mozilla/0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2019-10-15

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012384
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Purported MSIE 7 with terse HTTP Headers GET to PHP"; flow:established,to_server; content:".php"; http_uri; nocase; content:"Mozilla/4.0 (compatible|3b 20|MSIE 7.0|3b 20|Windows NT 5.1)"; http_user_agent; depth:50; isdataat:!1,relative; fast_pattern; http_protocol; content:"HTTP/1.1"; http_header_names; content:"|0d 0a|User-Agent|0d 0a|Host|0d 0a|"; depth:20; content:"Cache-Control|0d 0a 0d 0a|"; distance:0; classtype:trojan-activity; sid:2012384; rev:4; metadata:created_at 2011_02_27, updated_at 2019_10_16;)
` 

Name : **Suspicious Purported MSIE 7 with terse HTTP Headers GET to PHP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-27

Last modified date : 2019-10-16

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021025
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible ThousandEyes User-Agent Outbound"; flow:established,to_server; content:"Mozilla/5.0 AppleWebKit/999.0 (KHTML, like Gecko) Chrome/99.0 Safari/999.0"; http_user_agent; fast_pattern; depth:74; isdataat:!1,relative; reference:url,thousandeyes.com; classtype:misc-activity; sid:2021025; rev:3; metadata:created_at 2015_04_28, updated_at 2019_10_22;)
` 

Name : **Possible ThousandEyes User-Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,thousandeyes.com

CVE reference : Not defined

Creation date : 2015-04-28

Last modified date : 2019-10-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021026
`alert http any any -> $HTTP_SERVERS any (msg:"ET INFO Possible ThousandEyes User-Agent Inbound"; flow:established,to_server; content:"Mozilla/5.0 AppleWebKit/999.0 (KHTML, like Gecko) Chrome/99.0 Safari/999.0"; http_user_agent; fast_pattern; depth:74; isdataat:!1,relative; reference:url,thousandeyes.com; classtype:misc-activity; sid:2021026; rev:3; metadata:created_at 2015_04_28, updated_at 2019_10_22;)
` 

Name : **Possible ThousandEyes User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,thousandeyes.com

CVE reference : Not defined

Creation date : 2015-04-28

Last modified date : 2019-10-22

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022803
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Flowbit set for POST to Quicken Updater"; flow:established,to_server; content:"POST"; http_method; content:"quicken.com|0d 0a|"; http_header; content:"InetClntApp"; fast_pattern; depth:11; http_user_agent; content:"Date|3a|"; http_header; flowbits:set,ET.QuickenUpdater; flowbits:noalert; classtype:misc-activity; sid:2022803; rev:3; metadata:created_at 2016_05_11, updated_at 2020_02_18;)
` 

Name : **Flowbit set for POST to Quicken Updater** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-11

Last modified date : 2020-02-18

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029010
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Generic IOT Downloader Malware in GET (Outbound)"; flow:established,to_server; content:"GET "; depth:4; content:"wget http"; within:200; content:"|20 3b 20|chmod "; within:200; fast_pattern; content:"|20 3b 20|./"; within:100; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029010; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Major, created_at 2019_11_20, updated_at 2019_11_20;)
` 

Name : **Generic IOT Downloader Malware in GET (Outbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-20

Last modified date : 2019-11-20

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029012
`alert http $EXTERNAL_NET any -> any any (msg:"ET INFO Generic IOT Downloader Malware in GET (Inbound)"; flow:established,to_server; content:"GET "; depth:4; content:"wget http"; within:200; content:"|20 3b 20|chmod "; within:200; fast_pattern; content:"|20 3b 20|./"; within:100; classtype:bad-unknown; sid:2029012; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_20, updated_at 2019_11_20;)
` 

Name : **Generic IOT Downloader Malware in GET (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-20

Last modified date : 2019-11-20

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003492
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Mozilla User-Agent - Likely Fake (Mozilla/4.0)"; flow:established,to_server; content:"User-Agent|3a 20|Mozilla/4.0|0d 0a|"; fast_pattern; nocase; http_header; content:!"/CallParrotWebClient/"; http_uri; content:!"Cookie|3a 20|PREF|3d|ID|3d|"; nocase; http_raw_header; content:!"www.google.com"; http_host; content:!"secure.logmein.com"; http_host; content:!"weixin.qq.com"; http_host; content:!"slickdeals.net"; http_host; content:!"cloudera.com"; http_host; content:!"secure.digitalalchemy.net.au"; http_host; content:!".ksmobile.com"; http_host; content:!"gstatic.com"; http_host; content:!".cmcm.com"; http_host; content:!".deckedbuilder.com"; http_host; content:!".mobolize.com"; http_host; content:!"wq.cloud.duba.net"; http_host; content:!"infoc2.duba.net"; http_host; content:!".bitdefender.net"; http_host; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2003492; classtype:bad-unknown; sid:2003492; rev:33; metadata:created_at 2010_07_30, updated_at 2019_11_20;)
` 

Name : **Suspicious Mozilla User-Agent - Likely Fake (Mozilla/4.0)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2003492

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-11-20

Rev version : 30

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029216
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Chmod Usage in URI (Outbound)"; flow:to_server,established; content:"chmod"; fast_pattern; nocase; http_uri; pcre:"/^(?:\+|\x2520|\x24IFS|\x252B|\s)+(?:x|[0-9]{3,4})/URi"; content:!"&launchmode="; http_uri; content:!"/chmod/"; http_uri; content:!"searchmod"; http_uri;  classtype:attempted-admin; sid:2029216; rev:2; metadata:affected_product Linux, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_12_31, updated_at 2019_12_31;)
` 

Name : **Suspicious Chmod Usage in URI (Outbound)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-12-31

Last modified date : 2019-12-31

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029257
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Lets Encrypt Certificate for Suspicious TLD (.top)"; flow:established,to_client; tls_cert_subject; content:".top"; isdataat:!1,relative; tls_cert_issuer; content:"Lets Encrypt"; metadata: former_category INFO; classtype:bad-unknown; sid:2029257; rev:1; metadata:deployment Perimeter, signature_severity Minor, created_at 2020_01_13, performance_impact Low, updated_at 2020_01_13;)
` 

Name : **Observed Lets Encrypt Certificate for Suspicious TLD (.top)** 

Attack target : Not defined

Description : Alerts on an inbound SSL/TLS Let's Encrypt certificate for a .top domain.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-01-13

Last modified date : 2020-01-13

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2029340
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO TLS Handshake Failure"; flow:established,to_client; dsize:7; content:"|15|"; depth:1; content:"|00 02 02 28|"; distance:2; within:4; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2029340; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_01_30, updated_at 2020_01_30;)
` 

Name : **TLS Handshake Failure** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-01-30

Last modified date : 2020-01-30

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029339
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Powershell Downloader with Start-Process Inbound M1"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"new-object System.Net.WebClient"; nocase; fast_pattern; content:".DownloadFile("; distance:0; content:"Start-Process"; distance:0; within:500; metadata: former_category HUNTING; reference:md5,b510f48b9ac735a197093ad5fb99b0ee; classtype:bad-unknown; sid:2029339; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_01_29, updated_at 2020_01_31;)
` 

Name : **Powershell Downloader with Start-Process Inbound M1** 

Attack target : Client_Endpoint

Description : Signature triggers on Powershell usage to download and start a process

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : md5,b510f48b9ac735a197093ad5fb99b0ee

CVE reference : Not defined

Creation date : 2020-01-29

Last modified date : 2020-01-31

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029421
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious EXE requested with Java UA"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; isdataat:!1,relative; content:"User-Agent|3a 20|Java/"; http_header; fast_pattern; metadata: former_category HUNTING; classtype:misc-activity; sid:2029421; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_02_12, updated_at 2020_02_12;)
` 

Name : **Suspicious EXE requested with Java UA** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-02-12

Last modified date : 2020-02-12

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029424
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO [TGI] Entrust Entelligence Security Provider (Flowbits Set)"; flow:established,to_server; content:"Entrust Entelligence Security Provider"; http_user_agent; flowbits:set,ET.entrust_entelligence; flowbits:noalert; threshold:type limit, track by_src, seconds 60, count 1; metadata: former_category HUNTING; reference:url,www.entrustdatacard.com/products/pki/entrust-entelligence-security-provider; classtype:trojan-activity; sid:2029424; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2020_02_12, updated_at 2020_02_12;)
` 

Name : **[TGI] Entrust Entelligence Security Provider (Flowbits Set)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,www.entrustdatacard.com/products/pki/entrust-entelligence-security-provider

CVE reference : Not defined

Creation date : 2020-02-12

Last modified date : 2020-02-12

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029425
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO [TGI] Possible Cobalt Strike Extra Whitespace HTTP Response"; flow:established,to_client; content:!"WEBrick"; http_header; http_start; content:"HTTP/1.1|20|200|20|OK|20 0d 0a|Content-Type|3a|"; flowbits:isnotset,ET.entrust_entelligence; threshold:type limit, track by_src, seconds 60, count 1; metadata: former_category HUNTING; reference:url,github.com/fox-it/cobaltstrike-extraneous-space; classtype:trojan-activity; sid:2029425; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2020_02_12, updated_at 2020_02_12;)
` 

Name : **[TGI] Possible Cobalt Strike Extra Whitespace HTTP Response** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,github.com/fox-it/cobaltstrike-extraneous-space

CVE reference : Not defined

Creation date : 2020-02-12

Last modified date : 2020-02-12

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022652
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible WinHttpRequest (no .exe)"; flow:to_server,established; content:"Mozilla/4.0 (compatible|3b 20|Win32|3b 20|WinHttp.WinHttpRequest.5)"; http_user_agent; fast_pattern; content:!".exe"; nocase; http_uri; content:!".msi"; nocase; http_uri; content:!".msp"; nocase; http_uri; http_header_names; content:!"Cookie|0d 0a|"; content:!"Referer|0d 0a|"; content:!"Accept-Language|0d 0a|"; content:!"UA-CPU|0d 0a|"; flowbits:set,et.MS.WinHttpRequest.no.exe.request; flowbits:noalert; classtype:misc-activity; sid:2022652; rev:3; metadata:created_at 2016_03_24, updated_at 2020_02_21;)
` 

Name : **Possible WinHttpRequest (no .exe)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-03-24

Last modified date : 2020-02-21

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029549
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Bit.do Shortened Link Request (set)"; flow:established,to_server; content:"GET"; http_method; content:"Host|3a 20|bit.do|0d 0a|Connection|3a 20|Keep-Alive|0d 0a|"; http_header; depth:38; fast_pattern; http_header_names; content:"|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; depth:22; isdataat:!1,relative; flowbits:set,ET.bit.do.shortener; metadata: former_category INFO; classtype:misc-activity; sid:2029549; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_02_28, updated_at 2020_02_28;)
` 

Name : **Bit.do Shortened Link Request (set)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-02-28

Last modified date : 2020-02-28

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029550
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Bit.do Shortened Link Request to EXE"; flow:established,to_client; flowbits:isset,ET.bit.do.shortener; content:"30"; depth:2; http_stat_code; content:"30"; depth:2; http_stat_code; content:"Location|3a 20|"; http_header; content:".exe|0d 0a|"; http_header; distance:0; pcre:"/^Location\x3a\x20[^\r\n]+\.exe$/Hmi"; metadata: former_category HUNTING; classtype:misc-activity; sid:2029550; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_02_28, updated_at 2020_02_28;)
` 

Name : **Bit.do Shortened Link Request to EXE** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-02-28

Last modified date : 2020-02-28

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018358
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1"; flow:established,to_server; content:"POST"; http_method; content:" MSIE "; nocase; http_user_agent; fast_pattern; content:!"Mozilla/4.0 (compatible|3b 20|MSIE|20|6.0|3b 20|DynGate)"; http_user_agent; content:!"Windows Live Messenger"; http_user_agent; content:!"MS Web Services Client Protocol"; http_user_agent; content:!"groove.microsoft.com"; http_host; pcre:"/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/W"; content:!"grooveDNS|3a|//"; http_client_body; http_header_names; content:!"X-Requested-With"; nocase; content:!"Accept-Encoding"; content:!"Referer"; metadata: former_category INFO; classtype:bad-unknown; sid:2018358; rev:9; metadata:created_at 2014_04_04, updated_at 2020_03_03;)
` 

Name : **GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-04-04

Last modified date : 2020-03-03

Rev version : 9

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029573
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO EXE Downloaded from Github"; flow:established,to_client; content:"200"; http_stat_code; http_header_names; content:"|0d 0a|X-GitHub-Request-Id|0d 0a|"; fast_pattern; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; metadata: former_category HUNTING; classtype:misc-activity; sid:2029573; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, deployment SSLDecrypt, signature_severity Minor, created_at 2020_03_04, performance_impact Low, updated_at 2020_03_04;)
` 

Name : **EXE Downloaded from Github** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-04

Last modified date : 2020-03-04

Rev version : 2

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023670
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO IE7UA No Cookie No Referer"; flow:to_server,established; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b 20|MSIE 7.0|3b|"; http_header; fast_pattern; http_header_names; content:!"Referer|0d 0a|"; content:!"Cookie|0d 0a|"; flowbits:set,et.IE7.NoRef.NoCookie; flowbits:noalert; classtype:bad-unknown; sid:2023670; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2016_12_19, malware_family Trojan_Kwampirs, updated_at 2020_03_04;)
` 

Name : **IE7UA No Cookie No Referer** 

Attack target : Client_Endpoint

Description : WSF/JS Downloader Delivered via zipped JS/WSF Early December 2016.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-12-19

Last modified date : 2020-03-04

Rev version : 4

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Trojan_Kwampirs

Type : SID

Performance Impact : Not defined

# 2029011
`alert http $EXTERNAL_NET any -> any any (msg:"ET INFO Generic IOT Downloader Malware in POST (Inbound)"; flow:established,to_server; content:"POST"; http_method; content:"wget"; http_client_body; content:".sh|3b 20|chmod +x "; within:200; fast_pattern; http_client_body; content:"|3b 20|./"; within:100; http_client_body; classtype:bad-unknown; sid:2029011; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2019_11_20, updated_at 2020_03_04;)
` 

Name : **Generic IOT Downloader Malware in POST (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-20

Last modified date : 2020-03-04

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029009
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Generic IOT Downloader Malware in POST (Outbound)"; flow:established,to_server; content:"POST"; http_method; content:"wget"; http_client_body; content:".sh|3b 20|chmod +x "; within:200; http_client_body; fast_pattern; content:"|3b 20|./"; within:100; http_client_body; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029009; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Major, created_at 2019_11_20, updated_at 2020_03_04;)
` 

Name : **Generic IOT Downloader Malware in POST (Outbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-20

Last modified date : 2020-03-04

Rev version : 2

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022049
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible MSXMLHTTP Request (no .exe)"; flow:to_server,established; content:!".exe"; nocase; http_uri; content:!".msi"; nocase; http_uri; content:!".msp"; nocase; http_uri; http_start; content:"HTTP/1.1|0d 0a|Accept|3a 20|*/*|0d 0a|Accept-Encoding|3a 20|gzip, deflate|0d 0a|User-Agent|3a 20|Mozilla/4.0 (compatible|3b 20|MSIE 7.0|3b 20|Windows NT"; fast_pattern; http_header_names; content:"|0d 0a|Accept|0d 0a|Accept-Encoding|0d 0a|User-Agent|0d 0a|Host|0d 0a|"; depth:45; content:!"Cookie|0d 0a|"; content:!"Referer|0d 0a|"; content:!"Accept-Language|0d 0a|"; content:!"UA-CPU|0d 0a|"; flowbits:set,et.MS.XMLHTTP.no.exe.request; flowbits:noalert; classtype:misc-activity; sid:2022049; rev:4; metadata:created_at 2015_11_09, updated_at 2020_03_06;)
` 

Name : **Possible MSXMLHTTP Request (no .exe)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-11-09

Last modified date : 2020-03-06

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029590
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Generic IOT Downloader Malware in GET (Inbound)"; flow:established,to_server; content:"GET"; http_method; content:"wget+http"; within:200; http_uri; content:"sh+/"; within:200; fast_pattern; http_uri; content:"rm+-rf"; within:100; http_uri; classtype:bad-unknown; sid:2029590; rev:1; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Minor, created_at 2020_03_09, updated_at 2020_03_09;)
` 

Name : **Generic IOT Downloader Malware in GET (Inbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-09

Last modified date : 2020-03-09

Rev version : 2

Category : HUNTING

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029589
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Generic IOT Downloader Malware in GET (Outbound)"; flow:established,to_server; content:"GET"; http_method; content:"wget+http"; within:200; http_uri; content:"sh+/"; within:200; fast_pattern; http_uri; content:"rm+-rf"; within:100; http_uri; classtype:bad-unknown; sid:2029589; rev:2; metadata:affected_product Linux, attack_target IoT, deployment Perimeter, signature_severity Major, created_at 2020_03_09, updated_at 2020_03_09;)
` 

Name : **Generic IOT Downloader Malware in GET (Outbound)** 

Attack target : IoT

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-09

Last modified date : 2020-03-09

Rev version : 2

Category : INFO

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029634
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspected Malicious Telegram Communication (POST)"; flow:established,to_server; content:"|0d 0a|Accept-Language|3a 20|en-US,*|0d 0a|User-Agent|3a 20|Mozilla/5.0|0d 0a|Host|3a 20|"; http_header; fast_pattern; pcre:"/^[\x20-\x7e\r\n]{0,20}[^\x20-\x7e\r\n]/P"; http_content_len; byte_test:0,=,40,0,string,dec; http_request_line; content:"POST /api HTTP/1.1"; depth:18; isdataat:!1,relative; http_content_type; content:"application/x-www-form-urlencoded"; depth:33; isdataat:!1,relative; http_header_names; content:"|0d 0a|Content-Type|0d 0a|Content-Length|0d 0a|Connection|0d 0a|Accept-Encoding|0d 0a|Accept-Language|0d 0a|User-Agent|0d 0a|Host|0d 0a 0d 0a|"; depth:98; isdataat:!1,relative; metadata: former_category HUNTING; reference:md5,fe5338aee73b3aae375d7192067dc5c8; reference:url,www.amnesty.org/en/latest/research/2020/03/targeted-surveillance-attacks-in-uzbekistan-an-old-threat-with-new-techniques/; classtype:misc-activity; sid:2029634; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_12, performance_impact Low, updated_at 2020_03_12;)
` 

Name : **Suspected Malicious Telegram Communication (POST)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : md5,fe5338aee73b3aae375d7192067dc5c8|url,www.amnesty.org/en/latest/research/2020/03/targeted-surveillance-attacks-in-uzbekistan-an-old-threat-with-new-techniques/

CVE reference : Not defined

Creation date : 2020-03-12

Last modified date : 2020-03-12

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2029703
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Lets Encrypt Certificate - Possible COVID-19 Related M1"; flow:established,to_client; tls_cert_subject; content:"covid"; nocase; fast_pattern; tls_cert_issuer; content:"Lets Encrypt"; classtype:bad-unknown; sid:2029703; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_03_23;)
` 

Name : **Observed Lets Encrypt Certificate - Possible COVID-19 Related M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-03-23

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029704
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Observed Lets Encrypt Certificate - Possible COVID-19 Related M2"; flow:established,to_client; tls_cert_subject; content:"corona"; nocase; fast_pattern; tls_cert_issuer; content:"Lets Encrypt"; classtype:bad-unknown; sid:2029704; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_03_23;)
` 

Name : **Observed Lets Encrypt Certificate - Possible COVID-19 Related M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-03-23

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029709
`alert dns $HOME_NET any -> any any (msg:"ET INFO Suspicious Domain Request for Possible COVID-19 Domain M1"; dns_query; content:"covid"; nocase; classtype:bad-unknown; sid:2029709; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_03_23;)
` 

Name : **Suspicious Domain Request for Possible COVID-19 Domain M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-03-23

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029710
`alert dns $HOME_NET any -> any any (msg:"ET INFO Suspicious Domain Request for Possible COVID-19 Domain M2"; dns_query; content:"corona"; nocase; classtype:bad-unknown; sid:2029710; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_03_23;)
` 

Name : **Suspicious Domain Request for Possible COVID-19 Domain M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-03-23

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029714
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious POST Request with Possible COVID-19 Domain M2"; content:"POST"; http_method; content:"corona"; http_host; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029714; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Suspicious POST Request with Possible COVID-19 Domain M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029713
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious POST Request with Possible COVID-19 Domain M1"; content:"POST"; http_method; content:"covid"; http_host; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029713; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Suspicious POST Request with Possible COVID-19 Domain M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029712
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious GET Request with Possible COVID-19 Domain M2"; content:"GET"; http_method; content:"corona"; http_host; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029712; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Suspicious GET Request with Possible COVID-19 Domain M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029711
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious GET Request with Possible COVID-19 Domain M1"; content:"GET"; http_method; content:"covid"; http_host; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029711; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Suspicious GET Request with Possible COVID-19 Domain M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029756
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious POST Request with Possible COVID-19 URI M2"; content:"POST"; http_method; content:"corona"; nocase; http_uri; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029756; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_28, updated_at 2020_04_02;)
` 

Name : **Suspicious POST Request with Possible COVID-19 URI M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-28

Last modified date : 2020-04-02

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029755
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious POST Request with Possible COVID-19 URI M1"; content:"POST"; http_method; content:"covid"; nocase; http_uri; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029755; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_28, updated_at 2020_04_02;)
` 

Name : **Suspicious POST Request with Possible COVID-19 URI M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-28

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029754
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious GET Request with Possible COVID-19 URI M2"; content:"GET"; http_method; content:"corona"; http_uri; nocase; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029754; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_28, updated_at 2020_04_02;)
` 

Name : **Suspicious GET Request with Possible COVID-19 URI M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-28

Last modified date : 2020-04-02

Rev version : 3

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029753
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious GET Request with Possible COVID-19 URI M1"; content:"GET"; http_method; content:"covid"; http_uri; nocase; content:!".jhu.edu"; http_host; isdataat:!1,relative; content:!".ncsc.gov.ie"; http_host; isdataat:!1,relative; content:!".nhs.wales"; http_host; isdataat:!1,relative; content:!".govt.nz"; http_host; isdataat:!1,relative; content:!".nhp.gov.in"; http_host; isdataat:!1,relative; content:!".oracle.com"; http_host; isdataat:!1,relative; content:!".cdc.gov"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029753; rev:2; metadata:created_at 2020_03_28, updated_at 2020_04_02;)
` 

Name : **Suspicious GET Request with Possible COVID-19 URI M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-28

Last modified date : 2020-04-02

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029708
`alert tls any any -> any any (msg:"ET INFO Suspicious TLS SNI Request for Possible COVID-19 Domain M2"; flow:established,to_server; tls_sni; content:"corona"; nocase; content:!".jhu.edu"; isdataat:!1,relative; content:!".ncsc.gov.ie"; isdataat:!1,relative; content:!".nhs.wales"; isdataat:!1,relative; content:!".govt.nz"; isdataat:!1,relative; content:!".nhp.gov.in"; isdataat:!1,relative; content:!".oracle.com"; isdataat:!1,relative; content:!".cdc.gov"; isdataat:!1,relative; classtype:bad-unknown; sid:2029708; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Suspicious TLS SNI Request for Possible COVID-19 Domain M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 3

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029705
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible COVID-19 Domain in SSL Certificate M1"; flow:established,to_client; tls_cert_subject; content:"corona"; nocase; content:!".jhu.edu"; isdataat:!1,relative; content:!".ncsc.gov.ie"; isdataat:!1,relative; content:!".nhs.wales"; isdataat:!1,relative; content:!".govt.nz"; isdataat:!1,relative; content:!".nhp.gov.in"; isdataat:!1,relative; content:!".oracle.com"; isdataat:!1,relative; content:!".cdc.gov"; isdataat:!1,relative; classtype:bad-unknown; sid:2029705; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Possible COVID-19 Domain in SSL Certificate M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 3

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029706
`alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Possible COVID-19 Domain in SSL Certificate M2"; flow:established,to_client; tls_cert_subject; content:"covid"; nocase; content:!".jhu.edu"; isdataat:!1,relative; content:!".ncsc.gov.ie"; isdataat:!1,relative; content:!".nhs.wales"; isdataat:!1,relative; content:!".govt.nz"; isdataat:!1,relative; content:!".nhp.gov.in"; isdataat:!1,relative; content:!".oracle.com"; isdataat:!1,relative; content:!".cdc.gov"; isdataat:!1,relative; classtype:bad-unknown; sid:2029706; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_02;)
` 

Name : **Possible COVID-19 Domain in SSL Certificate M2** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-02

Rev version : 3

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015483
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Java .jar request to dotted-quad domain"; flow:established,to_server; content:".jar"; http_uri; fast_pattern; content:" Java/1"; http_header; pcre:"/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/W"; classtype:bad-unknown; sid:2015483; rev:5; metadata:created_at 2012_07_17, updated_at 2020_04_06;)
` 

Name : **Java .jar request to dotted-quad domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-17

Last modified date : 2020-04-06

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027250
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host DLL Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.dll; flowbits:unset,http.dottedquadhost; http_request_line; content:".dll HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027250; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Moderate, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host DLL Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a DLL from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2027251
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host DOC Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.doc; flowbits:unset,http.dottedquadhost; http_request_line; content:".doc HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027251; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host DOC Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a DOC from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027252
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host DOCX Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.docx; flowbits:unset,http.dottedquadhost; http_request_line; content:".docx HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027252; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host DOCX Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a DOCX from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027253
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host XLS Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.xls; flowbits:unset,http.dottedquadhost; http_request_line; content:".xls HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027253; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host XLS Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a XLS from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027254
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host XLSX Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.xlsx; flowbits:unset,http.dottedquadhost; http_request_line; content:".xlsx HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027254; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host XLSX Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a XLSX from an IP address. 

Tags : Phishing

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027255
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host PPT Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.ppt; flowbits:unset,http.dottedquadhost; http_request_line; content:".ppt HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027255; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host PPT Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a PPT from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027256
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host PPTX Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.pptx; flowbits:unset,http.dottedquadhost; http_request_line; content:".pptx HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027256; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host PPTX Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a PPTX from an IP address. 

Tags : Phishing

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027257
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host RTF Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.rtf; flowbits:unset,http.dottedquadhost; http_request_line; content:".rtf HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027257; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host RTF Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a RTF from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027258
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host PS Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.ps; flowbits:unset,http.dottedquadhost; http_request_line; content:".ps HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027258; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host PS Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a PS from an IP address. 

Tags : Phishing

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027259
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host PS1 Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.ps1; flowbits:unset,http.dottedquadhost; http_request_line; content:".ps1 HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027259; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host PS1 Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a PS1 from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027260
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host VBS Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.vbs; flowbits:unset,http.dottedquadhost; http_request_line; content:".vbs HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027260; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host VBS Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a VBS from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027261
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host HTA Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.hta; flowbits:unset,http.dottedquadhost; http_request_line; content:".hta HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027261; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Moderate, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host HTA Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a HTA from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate

# 2027262
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host ZIP Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.zip; flowbits:unset,http.dottedquadhost; http_request_line; content:".zip HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027262; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host ZIP Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a ZIP from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027263
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host GZ Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.gz; flowbits:unset,http.dottedquadhost; http_request_line; content:".gz HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027263; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host GZ Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a GZ from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027264
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host TGZ Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.tgz; flowbits:unset,http.dottedquadhost; http_request_line; content:".tgz HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027264; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host TGZ Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a TGZ from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027265
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host PDF Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.pdf; flowbits:unset,http.dottedquadhost; http_request_line; content:".pdf HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027265; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host PDF Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a PDF from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2027266
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dotted Quad Host RAR Request"; flow:established,from_client; flowbits:isset,http.dottedquadhost; flowbits:set,http.dottedquadhost.rar; flowbits:unset,http.dottedquadhost; http_request_line; content:".rar HTTP/1."; nocase; fast_pattern; metadata: former_category INFO; classtype:bad-unknown; sid:2027266; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_23, performance_impact Significant, updated_at 2020_04_08;)
` 

Name : **Dotted Quad Host RAR Request** 

Attack target : Client_Endpoint

Description : A possibly suspicious request for a RAR from an IP address. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2020-04-08

Rev version : 4

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2029840
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Request for EXE via WinHTTP M1"; flow:established,to_server; content:"GET"; http_method; content:".exe"; isdataat:!1,relative; http_uri; content:"Mozilla/4.0 (compatible|3b 20|Win32|3b 20|WinHttp.WinHttpRequest.5)"; http_user_agent; depth:57; isdataat:!1,relative; fast_pattern; http_header_names; content:!"Referer"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029840; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Request for EXE via WinHTTP M1** 

Attack target : Client_Endpoint

Description : This will alert on a request for an EXE with a WinHTTP library user-agent.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029841
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Request for EXE via WinHTTP M2"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; isdataat:!1,relative; content:"WinHTTP"; depth:7; http_user_agent; content:"User-Agent|3a 20|WinHTTP"; http_header; fast_pattern; http_header_names; content:!"Referer"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029841; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Request for EXE via WinHTTP M2** 

Attack target : Client_Endpoint

Description : This will alert on a request for an EXE with a WinHTTP library user-agent.


Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029842
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Request for EXE via WinHTTP M3"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; isdataat:!1,relative; content:"WinHttp-Autoproxy-Service/"; depth:26; fast_pattern; http_header_names; content:!"Referer"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029842; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Request for EXE via WinHTTP M3** 

Attack target : Client_Endpoint

Description : This will alert on a request for an EXE with a WinHTTP library user-agent.


Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029843
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Zipped Filename in Outbound POST Request (Hardware.txt)"; flow:established,to_server; content:"POST"; http_method; content:"Content-Disposition|3a 20|form-data|3b 20|name="; http_client_body; content:"|0d 0a|PK"; http_client_body; distance:0; content:"Hardware.txt"; http_client_body; distance:0; nocase; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029843; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Suspicious Zipped Filename in Outbound POST Request (Hardware.txt)** 

Attack target : Client_Endpoint

Description : This will alert on a commonly observed filename being exfiltrated from an infected system.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029844
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Zipped Filename in Outbound POST Request (Prgrm.txt)"; flow:established,to_server; content:"POST"; http_method; content:"Content-Disposition|3a 20|form-data|3b 20|name="; http_client_body; content:"|0d 0a|PK"; http_client_body; distance:0; content:"Prgrm.txt"; http_client_body; distance:0; nocase; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029844; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Suspicious Zipped Filename in Outbound POST Request (Prgrm.txt)** 

Attack target : Client_Endpoint

Description : This will alert on a commonly observed filename being exfiltrated from an infected system.


Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029845
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Suspicious Zipped Filename in Outbound POST Request (CookiesList.txt)"; flow:established,to_server; content:"POST"; http_method; content:"Content-Disposition|3a 20|form-data|3b 20|name="; http_client_body; content:"|0d 0a|PK"; http_client_body; distance:0; content:"CookiesList.txt"; http_client_body; distance:0; nocase; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2029845; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_09, updated_at 2020_04_09;)
` 

Name : **Suspicious Zipped Filename in Outbound POST Request (CookiesList.txt)** 

Attack target : Client_Endpoint

Description : This will alert on a commonly observed filename being exfiltrated from an infected system.


Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-09

Last modified date : 2020-04-09

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029954
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.parody)"; dns_query; content:".parody"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029954; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.parody)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029955
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.oz)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|02|oz|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029955; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.oz)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029956
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.cyb)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|cyb|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029956; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.cyb)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029957
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.geek)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|04|geek|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029957; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.geek)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029958
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.libre)"; dns_query; content:".libre"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029958; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.libre)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029959
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.dyn)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|dyn|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029959; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.dyn)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029960
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.bbs)"; dns_query; content:".bbs"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029960; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.bbs)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029961
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.neo)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|neo|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029961; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.neo)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029962
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.o)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|01|o|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029962; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.o)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029963
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.null)"; dns_query; content:".null"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029963; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.null)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029964
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.pirate)"; dns_query; content:".pirate"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029964; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.pirate)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029965
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.chan)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|04|chan|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029965; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.chan)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029966
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.oss)"; dns_query; content:".oss"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029966; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.oss)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029967
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.epic)"; dns_query; content:".epic"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029967; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.epic)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029968
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.indy)"; dns_query; content:".indy"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029968; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.indy)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029969
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for OpenNIC Alternative DNS TLD (.gopher)"; dns_query; content:".gopher"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029969; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for OpenNIC Alternative DNS TLD (.gopher)** 

Attack target : Client_Endpoint

Description : Signature triggers on a query for an OpenNIC managed TLD

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029970
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for EmerDNS TLD (.lib)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|lib|00|"; nocase; distance:0; fast_pattern; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; reference:url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction; classtype:bad-unknown; sid:2029970; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for EmerDNS TLD (.lib)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot|url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029971
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for EmerDNS TLD (.coin)"; dns_query; content:".coin"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; reference:url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction; classtype:bad-unknown; sid:2029971; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for EmerDNS TLD (.coin)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot|url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029972
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for EmerDNS TLD (.emc)"; dns_query; content:".emc"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; reference:url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction; classtype:bad-unknown; sid:2029972; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for EmerDNS TLD (.emc)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot|url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029973
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for EmerDNS TLD (.bazar)"; dns_query; content:".bazar"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,wiki.opennic.org/opennic/dot; reference:url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction; classtype:bad-unknown; sid:2029973; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for EmerDNS TLD (.bazar)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot|url,emercoin.com/en/documentation/blockchain-services/emerdns/emerdns-introduction

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029974
`alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query for FurNIC TLD (.fur)"; dns_query; content:".fur"; nocase; isdataat:!1,relative; reference:url,wiki.opennic.org/opennic/dot; classtype:bad-unknown; sid:2029974; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_20, updated_at 2020_04_20;)
` 

Name : **Observed DNS Query for FurNIC TLD (.fur)** 

Attack target : Client_Endpoint

Description : Signature triggers on query for FurNIC managed TLDs

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wiki.opennic.org/opennic/dot

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : INFO

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029707
`alert tls any any -> any any (msg:"ET INFO Suspicious TLS SNI Request for Possible COVID-19 Domain M1"; flow:established,to_server; tls_sni; content:"covid"; nocase; content:!".jhu.edu"; isdataat:!1,relative; content:!".ncsc.gov.ie"; isdataat:!1,relative; content:!".nhs.wales"; isdataat:!1,relative; content:!".govt.nz"; isdataat:!1,relative; content:!".nhp.gov.in"; isdataat:!1,relative; content:!".oracle.com"; isdataat:!1,relative; content:!".cdc.gov"; isdataat:!1,relative; content:!"covid19.wisc.edu"; isdataat:!1,relative; classtype:bad-unknown; sid:2029707; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_23, updated_at 2020_04_20;)
` 

Name : **Suspicious TLS SNI Request for Possible COVID-19 Domain M1** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-23

Last modified date : 2020-04-20

Rev version : 4

Category : HUNTING

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

