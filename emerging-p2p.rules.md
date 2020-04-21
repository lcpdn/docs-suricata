# 2008591
`alert tcp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET P2P Ares Server Connection"; flow:established,to_server; dsize:<70; content:"r|be|bloop|00|dV"; content:"Ares|00 0a|"; distance:16; reference:url,aresgalaxy.sourceforge.net; reference:url,doc.emergingthreats.net/bin/view/Main/2008591; classtype:policy-violation; sid:2008591; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Ares Server Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,aresgalaxy.sourceforge.net|url,doc.emergingthreats.net/bin/view/Main/2008591

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000369
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6969 (msg:"ET P2P BitTorrent Announce"; flow: to_server,established; content:"/announce"; reference:url,bitconjurer.org/BitTorrent/protocol.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000369; classtype:policy-violation; sid:2000369; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent Announce** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,bitconjurer.org/BitTorrent/protocol.html|url,doc.emergingthreats.net/bin/view/Main/2000369

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003308
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey IP Request"; dsize:4; content:"|e3 1b|"; depth:2; flowbits:set,BEedk.ip.requestect; flowbits:noalert; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003308; classtype:policy-violation; sid:2003308; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey IP Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003308

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003309
`#alert udp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET P2P Edonkey IP Reply"; flowbits:isset,BEedk.ip.requestect; dsize:<20; content:"|e3 1c|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003309; classtype:policy-violation; sid:2003309; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey IP Reply** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003309

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003316
`#alert udp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET P2P Edonkey IP Query End"; dsize:<20; content:"|e3 1d|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003316; classtype:policy-violation; sid:2003316; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey IP Query End** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003316

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003311
`alert udp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET P2P Edonkey Publicize File ACK"; dsize:<20; content:"|e3 0d|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003311; classtype:policy-violation; sid:2003311; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Publicize File ACK** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003311

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003312
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey Connect Request"; dsize:25; content:"|e3 0a|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003312; classtype:policy-violation; sid:2003312; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Connect Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003312

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003314
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey Search Request (by file hash)"; dsize:19; content:"|e3 0e 14|"; depth:3; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003314; classtype:policy-violation; sid:2003314; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Search Request (by file hash)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003314

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003318
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey Get Sources Request (by hash)"; dsize:19; content:"|e3 9a|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003318; classtype:policy-violation; sid:2003318; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Get Sources Request (by hash)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003318

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003324
`#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 4660:4799 (msg:"ET P2P Edonkey Server Status"; flow:established; dsize:14; content:"|e3 09 00 00 00 34|"; depth:6; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003324; classtype:policy-violation; sid:2003324; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Server Status** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003324

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002760
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P GnucDNA UDP Ultrapeer Traffic"; content:"SCP@|83|DNA@"; threshold: type both,track by_src,count 10,seconds 600; reference:url,doc.emergingthreats.net/bin/view/Main/2002760; classtype:policy-violation; sid:2002760; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GnucDNA UDP Ultrapeer Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002760

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001796
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Kazaa over UDP"; content:"KaZaA"; nocase; threshold: type threshold, track by_src,count 10, seconds 60; reference:url,www.kazaa.com/us/index.htm; reference:url,doc.emergingthreats.net/bin/view/Main/2001796; classtype:policy-violation; sid:2001796; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kazaa over UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.kazaa.com/us/index.htm|url,doc.emergingthreats.net/bin/view/Main/2001796

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009097
`alert udp $EXTERNAL_NET 41170 -> $HOME_NET any (msg:"ET P2P Manolito Connection (1)"; dsize:<48; content:"|3d 4a d9|"; depth:3; reference:url,doc.emergingthreats.net/2009097; classtype:policy-violation; sid:2009097; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Manolito Connection (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2009097

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009098
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 41170 (msg:"ET P2P Manolito Ping"; dsize:<24; content:"|3d|"; depth:1; content:"|d9|"; distance:1; content:"|ed bb|"; distance:13; threshold: type limit, track by_src, seconds 300, count 1; reference:url,doc.emergingthreats.net/2009098; classtype:policy-violation; sid:2009098; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Manolito Ping** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2009098

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009986
`alert udp $HOME_NET 8247 -> $EXTERNAL_NET 8247 (msg:"ET P2P Octoshape UDP Session"; threshold: type both, count 2, seconds 60, track by_src; reference:url,msmvps.com/blogs/bradley/archive/2009/01/20/peer-to-peer-on-cnn.aspx; reference:url,doc.emergingthreats.net/2009986; classtype:trojan-activity; sid:2009986; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Octoshape UDP Session** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,msmvps.com/blogs/bradley/archive/2009/01/20/peer-to-peer-on-cnn.aspx|url,doc.emergingthreats.net/2009986

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000015
`alert tcp any any -> any any (msg:"ET P2P Phatbot Control Connection"; flow: established; content:"Wonk-"; content:"|00|#waste|00|"; within: 15; reference:url,www.lurhq.com/phatbot.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000015; classtype:trojan-activity; sid:2000015; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Phatbot Control Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.lurhq.com/phatbot.html|url,doc.emergingthreats.net/bin/view/Main/2000015

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001187
`alert tcp $EXTERNAL_NET 2234 -> $HOME_NET any (msg:"ET P2P Soulseek Filesearch Results"; flow: from_server,established; content:"|09 00 00 00 78|"; reference:url,www.slsknet.org; reference:url,doc.emergingthreats.net/bin/view/Main/2001187; classtype:policy-violation; sid:2001187; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Soulseek Filesearch Results** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.slsknet.org|url,doc.emergingthreats.net/bin/view/Main/2001187

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002950
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: (msg:"ET P2P TOR 1.0 Server Key Retrieval"; flow:established,to_server; content:"GET /tor/server/"; depth:16; threshold:type limit, track by_src, count 1, seconds 30; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2002950; classtype:policy-violation; sid:2002950; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TOR 1.0 Server Key Retrieval** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2002950

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002951
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: (msg:"ET P2P TOR 1.0 Status Update"; flow:established,to_server; content:"GET /tor/status/"; depth:16; threshold:type limit, track by_src, count 1, seconds 60; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2002951; classtype:policy-violation; sid:2002951; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TOR 1.0 Status Update** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2002951

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002952
`alert tcp $EXTERNAL_NET any -> $HOME_NET 1024: (msg:"ET P2P TOR 1.0 Inbound Circuit Traffic"; flow:established; content:"TOR"; content:"<identity>"; rawbytes; distance:10; within:35; threshold:type limit, track by_src, count 1, seconds 120; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2002952; classtype:policy-violation; sid:2002952; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TOR 1.0 Inbound Circuit Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2002952

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002953
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: (msg:"ET P2P TOR 1.0 Outbound Circuit Traffic"; flow:established; content:"TOR"; content:"<identity>"; rawbytes; distance:10; within:35; threshold:type limit, track by_src, count 1, seconds 120; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2002953; classtype:policy-violation; sid:2002953; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TOR 1.0 Outbound Circuit Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2002953

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008581
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent DHT ping request"; content:"d1|3a|ad2|3a|id20|3a|"; depth:12; nocase; threshold: type both, count 1, seconds 300, track by_src; reference:url,wiki.theory.org/BitTorrentDraftDHTProtocol; reference:url,doc.emergingthreats.net/bin/view/Main/2008581; classtype:policy-violation; sid:2008581; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent DHT ping request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,wiki.theory.org/BitTorrentDraftDHTProtocol|url,doc.emergingthreats.net/bin/view/Main/2008581

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008585
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent DHT announce_peers request"; content:"d1|3a|ad2|3a|id20|3a|"; nocase; depth:14; content:"e1|3a|q13|3a|announce_peer1|3a|"; nocase; distance:55; threshold: type both, count 1, seconds 300, track by_src; reference:url,wiki.theory.org/BitTorrentDraftDHTProtocol; reference:url,doc.emergingthreats.net/bin/view/Main/2008585; classtype:policy-violation; sid:2008585; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent DHT announce_peers request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,wiki.theory.org/BitTorrentDraftDHTProtocol|url,doc.emergingthreats.net/bin/view/Main/2008585

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007800
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P LimeWire P2P Traffic"; flow: established; content:"Server|3a| LimeWire"; nocase; reference:url,www.limewire.com; reference:url,doc.emergingthreats.net/bin/view/Main/2007800; classtype:policy-violation; sid:2007800; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **LimeWire P2P Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.limewire.com|url,doc.emergingthreats.net/bin/view/Main/2007800

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010008
`alert udp $HOME_NET any -> $EXTERNAL_NET 8247 (msg:"ET P2P Octoshape P2P streaming media"; content:"POST / HTTP/1."; depth:64; content:"Oshtcp-streamtype|3a|"; threshold: type limit, track by_src, count 1, seconds 600; reference:url,doc.emergingthreats.net/2010008; classtype:policy-violation; sid:2010008; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Octoshape P2P streaming media** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010008

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003475
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET P2P ABC Torrent User-Agent (ABC/ABC-3.1.0)"; flow:to_server,established; content:"|0d 0a|User-Agent|3a| ABC/ABC"; nocase; reference:url,pingpong-abc.sourceforge.net; reference:url,doc.emergingthreats.net/bin/view/Main/2003475; classtype:trojan-activity; sid:2003475; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ABC Torrent User-Agent (ABC/ABC-3.1.0)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,pingpong-abc.sourceforge.net|url,doc.emergingthreats.net/bin/view/Main/2003475

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008583
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent DHT nodes reply"; content:"d1|3a|rd2|3a|id20|3a|"; nocase; depth:12; content:"5|3a|nodes"; nocase; distance:20; within:7; threshold: type both, count 1, seconds 300, track by_src; reference:url,wiki.theory.org/BitTorrentDraftDHTProtocol; reference:url,doc.emergingthreats.net/bin/view/Main/2008583; classtype:policy-violation; sid:2008583; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent DHT nodes reply** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,wiki.theory.org/BitTorrentDraftDHTProtocol|url,doc.emergingthreats.net/bin/view/Main/2008583

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002814
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Direct Connect Traffic (client-server)"; flow:from_client,established; content:"$MyINFO"; depth:7; reference:url,en.wikipedia.org/wiki/Direct_connect_file-sharing_application; reference:url,doc.emergingthreats.net/bin/view/Main/2002814; classtype:policy-violation; sid:2002814; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Direct Connect Traffic (client-server)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,en.wikipedia.org/wiki/Direct_connect_file-sharing_application|url,doc.emergingthreats.net/bin/view/Main/2002814

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001296
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 4660:4799 (msg:"ET P2P eDonkey File Status"; flow: to_server,established; content:"|e3 14|"; depth: 2; reference:url,www.edonkey.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001296; classtype:policy-violation; sid:2001296; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eDonkey File Status** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.edonkey.com|url,doc.emergingthreats.net/bin/view/Main/2001296

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001297
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 4660:4799 (msg:"ET P2P eDonkey File Status Request"; flow: to_server,established; content:"|e3 11|"; depth: 2; reference:url,www.edonkey.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001297; classtype:policy-violation; sid:2001297; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eDonkey File Status Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.edonkey.com|url,doc.emergingthreats.net/bin/view/Main/2001297

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001298
`alert udp $HOME_NET any -> $EXTERNAL_NET 4660:4799 (msg:"ET P2P eDonkey Server Status Request"; content:"|e3 96|"; depth: 2; reference:url,www.edonkey.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001298; classtype:policy-violation; sid:2001298; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eDonkey Server Status Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.edonkey.com|url,doc.emergingthreats.net/bin/view/Main/2001298

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001299
`#alert udp $HOME_NET 4660:4799 -> $EXTERNAL_NET any (msg:"ET P2P eDonkey Server Status"; content:"|e3 97|"; depth: 2; reference:url,www.edonkey.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001299; classtype:policy-violation; sid:2001299; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eDonkey Server Status** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.edonkey.com|url,doc.emergingthreats.net/bin/view/Main/2001299

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007801
`alert tcp any 1024: -> any 1024: (msg:"ET P2P Gnutella TCP Traffic"; flow: established,to_server; content:"GNUTELLA"; depth:8; content:"200 OK|0d 0a|"; within:15; threshold: type both,track by_src,count 5,seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2007801; classtype:policy-violation; sid:2007801; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gnutella TCP Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007801

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009966
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P KuGoo P2P Connection"; dsize:<30; content:"|64|"; depth:1; content:"|70|"; distance:5; content:"|50 37|"; distance:4; reference:url,koogoo.com; reference:url,doc.emergingthreats.net/2009966; classtype:policy-violation; sid:2009966; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **KuGoo P2P Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,koogoo.com|url,doc.emergingthreats.net/2009966

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000335
`#alert udp any any -> any any (msg:"ET P2P Overnet (Edonkey) Server Announce"; content:"|00 00 02 03 00 6c 6f 63|"; offset: 36; content:"|00 62 63 70 3a 2f 2f|"; distance: 1; reference:url,www.overnet.com; reference:url,doc.emergingthreats.net/bin/view/Main/2000335; classtype:policy-violation; sid:2000335; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Overnet (Edonkey) Server Announce** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.overnet.com|url,doc.emergingthreats.net/bin/view/Main/2000335

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008611
`alert tcp $EXTERNAL_NET 2240 -> $HOME_NET 1024: (msg:"ET P2P SoulSeek P2P Login Response"; flow:from_server,established; content:"|5c 01 00 00 01 00 00 00|"; depth:8; reference:url,www.slsknet.org; reference:url,doc.emergingthreats.net/2008611; classtype:policy-violation; sid:2008611; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SoulSeek P2P Login Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.slsknet.org|url,doc.emergingthreats.net/2008611

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010139
`alert tcp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Vuze BT Connection"; flow:established; content:"|00 00|"; depth:2; content:"|05|AZVER|01|"; distance:5; within:7; content:"appid"; within:10; threshold:type limit, track by_src, count 10, seconds 600; reference:url,vuze.com; reference:url,doc.emergingthreats.net/2010139; classtype:policy-violation; sid:2010139; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Vuze BT Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,vuze.com|url,doc.emergingthreats.net/2010139

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010141
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET any (msg:"ET P2P Vuze BT UDP Connection (2)"; dsize:94; content:"|00 00 04|"; depth:3; content:"|00 00 00 00 00|"; distance:14; within:5; content:"|ff ff ff ff 00 00 00 00 02 05 21|"; distance:8; within:11; content:"|00 00 00 00 00 00|"; distance:25; within:6; content:"|00 00|"; distance:20; within:2; reference:url,vuze.com; reference:url,doc.emergingthreats.net/2010141; classtype:policy-violation; sid:2010141; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Vuze BT UDP Connection (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,vuze.com|url,doc.emergingthreats.net/2010141

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010142
`alert udp $EXTERNAL_NET any -> $HOME_NET 1024:65535 (msg:"ET P2P Vuze BT UDP Connection (3)"; dsize:80; content:"|00 00 04|"; depth:3; content:"|00 00 00 00 00|"; distance:14; within:5; content:"|02 05 21 04|"; distance:4; within:4; threshold:type limit, track by_dst, count 10, seconds 600; reference:url,doc.emergingthreats.net/2010142; classtype:policy-violation; sid:2010142; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Vuze BT UDP Connection (3)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010142

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010143
`alert udp $EXTERNAL_NET any -> $HOME_NET 1024:65535 (msg:"ET P2P Vuze BT UDP Connection (4)"; dsize:<300; content:"|00 00 04|"; depth:3; content:"|00 00 00 00 00|"; distance:14; within:5; content:"|ff ff ff ff|"; distance:8; within:4; reference:url,doc.emergingthreats.net/2010143; classtype:policy-violation; sid:2010143; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Vuze BT UDP Connection (4)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010143

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009968
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule KAD Network Connection Request(2)"; dsize:35; content:"|e4 20|"; depth:2; threshold: type limit, count 5, seconds 600, track by_src; reference:url,emule-project.net; reference:url,doc.emergingthreats.net/2009968; classtype:policy-violation; sid:2009968; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule KAD Network Connection Request(2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,emule-project.net|url,doc.emergingthreats.net/2009968

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009969
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule KAD Network Firewalled Request"; dsize:35; content:"|e4 50|"; depth:2; threshold: type limit, count 5, seconds 600, track by_src; reference:url,emule-project.net; reference:url,doc.emergingthreats.net/2009969; classtype:policy-violation; sid:2009969; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule KAD Network Firewalled Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,emule-project.net|url,doc.emergingthreats.net/2009969

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009972
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule KAD Network Server Status Request"; dsize:44; content:"|8c 97|"; depth:2; threshold: type limit, count 5, seconds 600, track by_src; reference:url,emule-project.net; reference:url,doc.emergingthreats.net/2009972; classtype:policy-violation; sid:2009972; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule KAD Network Server Status Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,emule-project.net|url,doc.emergingthreats.net/2009972

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009973
`#alert tcp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule KAD Network Send Username"; flow:established; content:"|e3|"; depth:1; content:"|00 00 00 01|"; distance:1; within:4; byte_test:1,<,51,37; threshold: type limit, count 5, seconds 600, track by_src; reference:url, emule-project.net; reference:url,doc.emergingthreats.net/2009973; classtype:policy-violation; sid:2009973; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule KAD Network Send Username** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url, emule-project.net|url,doc.emergingthreats.net/2009973

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001664
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Gnutella Connect"; flow: established,to_server; content:"GNUTELLA CONNECT/"; nocase; depth:17; reference:url,www.gnutella.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001664; classtype:policy-violation; sid:2001664; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gnutella Connect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.gnutella.com|url,doc.emergingthreats.net/bin/view/Main/2001664

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002761
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Gnutella TCP Ultrapeer Traffic"; flow: established,to_server; content:"GNUTELLA"; depth:8; content:"X-Ultrapeer|3a| True"; nocase; threshold: type both,track by_src,count 5,seconds 3600; reference:url,doc.emergingthreats.net/bin/view/Main/2002761; classtype:policy-violation; sid:2002761; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gnutella TCP Ultrapeer Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002761

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001809
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Limewire P2P UDP Traffic"; dsize:35; content:"|49 50 40 83 53 43 50 41 00 00|"; offset:25; depth:10; threshold: type both, track by_src, count 1, seconds 360; reference:url,www.limewire.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001809; classtype:policy-violation; sid:2001809; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Limewire P2P UDP Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.limewire.com|url,doc.emergingthreats.net/bin/view/Main/2001809

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008584
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent DHT get_peers request"; content:"d1|3a|ad2|3a|id20|3a|"; nocase; offset:12; content:"9|3a|info_hash20|3a|"; nocase; distance:20; within:14; content:"e1|3a|q9|3a|get_peers1|3a|"; nocase; distance:20; threshold: type both, count 1, seconds 300, track by_src; reference:url,wiki.theory.org/BitTorrentDraftDHTProtocol; reference:url,doc.emergingthreats.net/bin/view/Main/2008584; classtype:policy-violation; sid:2008584; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent DHT get_peers request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,wiki.theory.org/BitTorrentDraftDHTProtocol|url,doc.emergingthreats.net/bin/view/Main/2008584

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000332
`alert tcp any any -> any 4660:4799 (msg:"ET P2P ed2k request part"; flow: to_server,established; content:"|e3|"; offset: 1; content:"|00 00 00 47|"; distance: 2; within: 4; reference:url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf; reference:url,doc.emergingthreats.net/bin/view/Main/2000332; classtype:policy-violation; sid:2000332; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ed2k request part** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf|url,doc.emergingthreats.net/bin/view/Main/2000332

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000333
`alert tcp any any -> any 4660:4799 (msg:"ET P2P ed2k file request answer"; flow: to_server,established; content:"|e3|"; offset: 1; content:"|00 00 00 59|"; distance: 2; within: 4; reference:url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf; reference:url,doc.emergingthreats.net/bin/view/Main/2000333; classtype:policy-violation; sid:2000333; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ed2k file request answer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf|url,doc.emergingthreats.net/bin/view/Main/2000333

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003323
`#alert tcp $HOME_NET 4660:4799 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey Client to Server Hello"; flow:established; dsize:>5; content:"|e3|"; offset:1; content:"|01|"; distance:4; within:5; content:"|02 01 00 01|"; distance:26; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003323; classtype:policy-violation; sid:2003323; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Client to Server Hello** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003323

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008595
`#alert tcp $HOME_NET 1024: -> $EXTERNAL_NET 2240 (msg:"ET P2P SoulSeek P2P Server Connection"; flow:established,to_server; content:"|01 00 00 00|"; offset:4; reference:url,www.slsknet.org; reference:url,doc.emergingthreats.net/2008595; classtype:policy-violation; sid:2008595; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SoulSeek P2P Server Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.slsknet.org|url,doc.emergingthreats.net/2008595

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000330
`#alert tcp any any -> any 4660:4799 (msg:"ET P2P ed2k connection to server"; flow: to_server,established; content:"|e3|"; depth:1; content:"|00 00 00 01|"; distance:2; within:4; reference:url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf; reference:url,doc.emergingthreats.net/bin/view/Main/2000330; classtype:policy-violation; sid:2000330; rev:13; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ed2k connection to server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf|url,doc.emergingthreats.net/bin/view/Main/2000330

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 13

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003321
`#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 4660:4799 (msg:"ET P2P Edonkey Server Message"; flow:established; dsize:>10; content:"|e3|"; depth:1; content:"|38|"; distance:4; within:5; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003321; classtype:policy-violation; sid:2003321; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Server Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003321

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003322
`#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 4660:4799 (msg:"ET P2P Edonkey Server List"; flow:established; dsize:>12; content:"|e3|"; depth:1; content:"|32|"; distance:4; within:5; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003322; classtype:policy-violation; sid:2003322; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Server List** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003322

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002673
`#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET P2P MS Foldershare Login Detected"; flow:established,to_client; content:"|0b|FolderShare|30 81 9f 30|"; nocase; offset:392; depth:18; reference:url,www.foldershare.com; reference:url,doc.emergingthreats.net/bin/view/Main/2002673; classtype:policy-violation; sid:2002673; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MS Foldershare Login Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.foldershare.com|url,doc.emergingthreats.net/bin/view/Main/2002673

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008582
`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent DHT find_node request"; content:"d1|3a|ad2|3a|id20|3a|"; nocase; depth:24; content:"6|3a|target20|3a|"; nocase; distance:20; content:"e1|3a|q9|3a|find_node1|3a|"; nocase; distance:20; content:"e1|3a|q9|3a|find_node1|3a|"; distance:20; nocase; threshold: type both, count 1, seconds 300, track by_src; reference:url,wiki.theory.org/BitTorrentDraftDHTProtocol; reference:url,doc.emergingthreats.net/bin/view/Main/2008582; classtype:policy-violation; sid:2008582; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent DHT find_node request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,wiki.theory.org/BitTorrentDraftDHTProtocol|url,doc.emergingthreats.net/bin/view/Main/2008582

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012467
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET P2P Ocelot BitTorrent Server in Use"; flow:established,from_server; content:"HTTP/1.1 200 |0d 0a|Server|3a| Ocelot "; depth:30; classtype:policy-violation; sid:2012467; rev:2; metadata:created_at 2011_03_10, updated_at 2011_03_10;)
` 

Name : **Ocelot BitTorrent Server in Use** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-10

Last modified date : 2011-03-10

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101699
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL P2P Fastrack kazaa/morpheus traffic"; flow:to_server,established; content:"GET "; depth:4; content:"UserAgent|3A| KazaaClient"; reference:url,www.kazaa.com; classtype:policy-violation; sid:2101699; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Fastrack kazaa/morpheus traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.kazaa.com

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001652
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P JoltID Agent New Code Download"; flow: established; content:"PeerEnabler"; http_header; fast_pattern:only; reference:url,www.joltid.com; reference:url,forum.treweeke.com/lofiversion/index.php/t597.html; reference:url,doc.emergingthreats.net/2001652; classtype:trojan-activity; sid:2001652; rev:34; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **JoltID Agent New Code Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.joltid.com|url,forum.treweeke.com/lofiversion/index.php/t597.html|url,doc.emergingthreats.net/2001652

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 34

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102181
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6881:6889 (msg:"GPL P2P BitTorrent transfer"; flow:to_server,established; content:"|13|BitTorrent protocol"; depth:20; classtype:policy-violation; sid:2102181; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **BitTorrent transfer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102180
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL P2P BitTorrent announce request"; flow:to_server,established; content:"GET"; http_method; content:"/announce"; http_uri; content:"info_hash="; http_uri; content:"event=started"; http_uri; classtype:policy-violation; sid:2102180; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **BitTorrent announce request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102584
`#alert tcp $EXTERNAL_NET 6666:6669 -> $HOME_NET any (msg:"GPL P2P eMule buffer overflow attempt"; flow:to_client,established; content:"PRIVMSG"; nocase; content:"|01|SENDLINK|7c|"; distance:0; pcre:"/^PRIVMSG\s+[^\s]+\s+\x3a\s*\x01SENDLINK\x7c[^\x7c]{69}/smi"; reference:bugtraq,10039; reference:nessus,12233; classtype:attempted-user; sid:2102584; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **eMule buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,10039|nessus,12233

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102587
`alert tcp any 4711 -> $HOME_NET any (msg:"GPL P2P eDonkey server response"; flow:established,from_server; content:"Server|3A| eMule"; reference:url,www.emule-project.net; classtype:policy-violation; sid:2102587; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **eDonkey server response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.emule-project.net

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014459
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P QVOD P2P Sharing Traffic detected (tcp)"; flow:established,from_client; content:"POST"; http_method; content:"/service"; http_uri; urilen:8; content:"|13|QVOD protocol|00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; classtype:policy-violation; sid:2014459; rev:2; metadata:created_at 2012_04_03, updated_at 2012_04_03;)
` 

Name : **QVOD P2P Sharing Traffic detected (tcp)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-03

Last modified date : 2012-04-03

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100557
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL P2P GNUTella client request"; flow:to_server,established; content:"GNUTELLA OK"; depth:40; classtype:policy-violation; sid:2100557; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GNUTella client request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101432
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL P2P GNUTella client request"; flow:to_server,established; content:"GNUTELLA"; depth:8; classtype:policy-violation; sid:2101432; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **GNUTella client request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100556
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL P2P Outbound GNUTella client request"; flow:to_server,established; content:"GNUTELLA CONNECT"; depth:40; classtype:policy-violation; sid:2100556; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Outbound GNUTella client request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006379
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BearShare P2P Gnutella Client HTTP Request "; flow:to_server,established; content:"/gnutella/"; nocase; http_uri; content:"?client=BEAR"; nocase; http_uri; content:"&version="; http_uri; reference:url,doc.emergingthreats.net/bin/view/Main/2006379; classtype:trojan-activity; sid:2006379; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BearShare P2P Gnutella Client HTTP Request ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006379

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011703
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (Enhanced CTorrent 3.x)"; flow:to_server,established; content:"Enhanced-CTorrent"; http_user_agent; reference:url,www.rahul.net/dholmes/ctorrent; reference:url,doc.emergingthreats.net/2011703; classtype:policy-violation; sid:2011703; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bittorrent P2P Client User-Agent (Enhanced CTorrent 3.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.rahul.net/dholmes/ctorrent|url,doc.emergingthreats.net/2011703

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011701
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (Opera/10.x)"; flow:to_server,established; content:"Opera BitTorrent, Opera/"; http_user_agent; reference:url,www.opera.com; reference:url,doc.emergingthreats.net/2011701; classtype:policy-violation; sid:2011701; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bittorrent P2P Client User-Agent (Opera/10.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.opera.com|url,doc.emergingthreats.net/2011701

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016662
`#alert udp $HOME_NET any -> any 53 (msg:"ET P2P Possible Bittorrent Activity - Multiple DNS Queries For tracker hosts"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|07|tracker"; fast_pattern; distance:0; threshold: type both, count 3, seconds 10, track by_src; classtype:policy-violation; sid:2016662; rev:3; metadata:created_at 2013_03_25, updated_at 2013_03_25;)
` 

Name : **Possible Bittorrent Activity - Multiple DNS Queries For tracker hosts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-25

Last modified date : 2013-03-25

Rev version : 3

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009967
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule KAD Network Connection Request"; dsize:35; content:"|e4 21|"; depth:2; threshold: type limit, count 1, seconds 300, track by_src; reference:url,emule-project.net; reference:url,doc.emergingthreats.net/2009967; classtype:policy-violation; sid:2009967; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule KAD Network Connection Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,emule-project.net|url,doc.emergingthreats.net/2009967

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018012
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Vagaa peer-to-peer (Transfer)"; flow:from_client,established; content:"VAGAA-OPERATION|3a| Transfer|0d 0a|"; http_header; reference:url,en.wikipedia.org/wiki/Vagaa; classtype:policy-violation; sid:2018012; rev:2; metadata:created_at 2014_01_27, updated_at 2014_01_27;)
` 

Name : **Vagaa peer-to-peer (Transfer)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,en.wikipedia.org/wiki/Vagaa

CVE reference : Not defined

Creation date : 2014-01-27

Last modified date : 2014-01-27

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013869
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Torrent Client User-Agent (Solid Core/0.82)"; flow:to_server,established; content:"User-Agent|3a| Solid Core/"; http_header; reference:url,sunbeltsecurity.com/partnerresources/cwsandbox/md5.aspx?id=4a9f376e8d01cb5f7990576ed927869b; classtype:policy-violation; sid:2013869; rev:7; metadata:created_at 2011_11_08, updated_at 2011_11_08;)
` 

Name : **Torrent Client User-Agent (Solid Core/0.82)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,sunbeltsecurity.com/partnerresources/cwsandbox/md5.aspx?id=4a9f376e8d01cb5f7990576ed927869b

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2011-11-08

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011706
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (uTorrent)"; flow:to_server,established; content:"uTorrent"; depth:8; http_user_agent;  reference:url,www.utorrent.com; reference:url,doc.emergingthreats.net/2011706; classtype:policy-violation; sid:2011706; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bittorrent P2P Client User-Agent (uTorrent)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.utorrent.com|url,doc.emergingthreats.net/2011706

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000357
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BitTorrent Traffic"; flow: established; content:"|0000400907000000|"; depth:8; threshold: type limit, count 1, seconds 120, track by_src; reference:url,bitconjurer.org/BitTorrent/protocol.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000357; classtype:policy-violation; sid:2000357; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,bitconjurer.org/BitTorrent/protocol.html|url,doc.emergingthreats.net/bin/view/Main/2000357

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010144
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET any (msg:"ET P2P Vuze BT UDP Connection (5)"; dsize:<20; content:"|00 00 04 17 27 10 19 80 00 00 00 00|"; depth:12; threshold: type limit, count 1, seconds 120, track by_src; reference:url,vuze.com; reference:url,doc.emergingthreats.net/2010144; classtype:policy-violation; sid:2010144; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Vuze BT UDP Connection (5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,vuze.com|url,doc.emergingthreats.net/2010144

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003437
`#alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Ares over UDP"; content:"Ares "; offset:36; depth:7; threshold: type limit, count 1, seconds 300, track by_src; reference:url,doc.emergingthreats.net/bin/view/Main/2003437; classtype:policy-violation; sid:2003437; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Ares over UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003437

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015966
`#alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P QVOD P2P Sharing Traffic detected (udp) beacon"; content:"|13|QVOD protocol|00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; depth:42; reference:md5,816a02a1250d90734059ed322ace72c7; classtype:policy-violation; sid:2015966; rev:2; metadata:created_at 2012_11_29, updated_at 2012_11_29;)
` 

Name : **QVOD P2P Sharing Traffic detected (udp) beacon** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,816a02a1250d90734059ed322ace72c7

CVE reference : Not defined

Creation date : 2012-11-29

Last modified date : 2012-11-29

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015967
`#alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P QVOD P2P Sharing Traffic detected (udp) payload"; content:"QVOD"; depth:32; reference:md5,816a02a1250d90734059ed322ace72c7; classtype:policy-violation; sid:2015967; rev:2; metadata:created_at 2012_11_29, updated_at 2012_11_29;)
` 

Name : **QVOD P2P Sharing Traffic detected (udp) payload** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,816a02a1250d90734059ed322ace72c7

CVE reference : Not defined

Creation date : 2012-11-29

Last modified date : 2012-11-29

Rev version : 2

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003315
`#alert udp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET P2P Edonkey Search Reply"; dsize:>200; content:"|e3 0f|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003315; classtype:policy-violation; sid:2003315; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Search Reply** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003315

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003310
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P Edonkey Publicize File"; dsize:>15; content:"|e3 0c|"; depth:2; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003310; classtype:policy-violation; sid:2003310; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Edonkey Publicize File** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003310

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009970
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024:65535 (msg:"ET P2P eMule Kademlia Hello Request"; dsize:<48; content:"|e4 11|"; depth:2; threshold: type limit, count 5, seconds 600, track by_src; reference:url,emule-project.net; reference:url,doc.emergingthreats.net/2009970; classtype:policy-violation; sid:2009970; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **eMule Kademlia Hello Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,emule-project.net|url,doc.emergingthreats.net/2009970

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000334
`alert tcp $HOME_NET any -> $EXTERNAL_NET !7680 (msg:"ET P2P BitTorrent peer sync"; flow:established; content:"|00 00 00 0d 06 00|"; depth:6; threshold: type limit, track by_dst, seconds 300, count 1; reference:url,bitconjurer.org/BitTorrent/protocol.html; reference:url,doc.emergingthreats.net/bin/view/Main/2000334; classtype:policy-violation; sid:2000334; rev:13; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BitTorrent peer sync** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,bitconjurer.org/BitTorrent/protocol.html|url,doc.emergingthreats.net/bin/view/Main/2000334

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 13

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022371
`alert tcp $HOME_NET any -> $EXTERNAL_NET 7680 (msg:"ET P2P MS WUDO Peer Sync"; flow:established; content:"|00 00 00 0d 06 00|"; depth:6; reference:url,bitconjurer.org/BitTorrent/protocol.html; reference:url,windows.microsoft.com/en-us/windows-10/windows-update-delivery-optimization-faq; classtype:policy-violation; sid:2022371; rev:1; metadata:created_at 2016_01_14, updated_at 2016_01_14;)
` 

Name : **MS WUDO Peer Sync** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,bitconjurer.org/BitTorrent/protocol.html|url,windows.microsoft.com/en-us/windows-10/windows-update-delivery-optimization-faq

CVE reference : Not defined

Creation date : 2016-01-14

Last modified date : 2016-01-14

Rev version : 1

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014734
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET P2P BitTorrent - Torrent File Downloaded"; flow:established,to_client; file_data; content:"d8|3a|announce"; within:11; content:!"mapfactor.com"; classtype:policy-violation; sid:2014734; rev:5; metadata:created_at 2012_05_10, updated_at 2012_05_10;)
` 

Name : **BitTorrent - Torrent File Downloaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-10

Last modified date : 2012-05-10

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010140
`alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 1024: (msg:"ET P2P Vuze BT UDP Connection"; dsize:<80; content:!"|00 22 02 00|"; depth: 4; content:"|00 00 04|"; distance:8; within:3; content:"|00 00 00 00 00|"; distance:6; within:5; threshold: type limit, count 1, seconds 120, track by_src; reference:url,vuze.com; reference:url,doc.emergingthreats.net/2010140; classtype:policy-violation; sid:2010140; rev:7; metadata:created_at 2010_07_30, updated_at 2016_11_01;)
` 

Name : **Vuze BT UDP Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,vuze.com|url,doc.emergingthreats.net/2010140

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-11-01

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007727
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P possible torrent download"; flow:established,to_server; content:".torrent"; nocase; http_uri; isdataat:!1,relative; content:!"mapfactor.com"; http_host; metadata: former_category P2P; reference:url,doc.emergingthreats.net/bin/view/Main/2007727; classtype:policy-violation; sid:2007727; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **possible torrent download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007727

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011699
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (Transmission/1.x)"; flow:established,to_server; content:"Transmission/"; depth:13; http_user_agent; metadata: former_category P2P; reference:url,www.transmissionbt.com; reference:url,doc.emergingthreats.net/2011699; classtype:policy-violation; sid:2011699; rev:6; metadata:created_at 2010_07_30, updated_at 2017_11_27;)
` 

Name : **Bittorrent P2P Client User-Agent (Transmission/1.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.transmissionbt.com|url,doc.emergingthreats.net/2011699

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-11-27

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011704
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (Deluge 1.x.x)"; flow:to_server,established; content:"Deluge"; http_user_agent; depth:6; reference:url,deluge-torrent.org; reference:url,doc.emergingthreats.net/2011704; classtype:policy-violation; sid:2011704; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bittorrent P2P Client User-Agent (Deluge 1.x.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,deluge-torrent.org|url,doc.emergingthreats.net/2011704

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003319
`alert udp $HOME_NET [!3389,1024:65535] -> $EXTERNAL_NET [!3389,1024:65535] (msg:"ET P2P Edonkey Search Request (search by name)"; dsize:>5; content:"|e3 98|"; depth:2; content:"|01|"; within:3; reference:url,www.giac.org/certified_professionals/practicals/gcih/0446.php; reference:url,doc.emergingthreats.net/bin/view/Main/2003319; classtype:policy-violation; sid:2003319; rev:4; metadata:created_at 2010_07_30, updated_at 2019_01_18;)
` 

Name : **Edonkey Search Request (search by name)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.giac.org/certified_professionals/practicals/gcih/0446.php|url,doc.emergingthreats.net/bin/view/Main/2003319

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-01-18

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009099
`alert udp $HOME_NET 1024:65535 -> [$EXTERNAL_NET,!224.0.0.0/4] 1024:65535 (msg:"ET P2P ThunderNetwork UDP Traffic"; dsize:<38; content:"|32 00 00 00|"; depth:4; content:"|00 00 00 00|"; distance:1; threshold:type limit, track by_src, count 1, seconds 300; reference:url,xunlei.com; reference:url,en.wikipedia.org/wiki/Xunlei; reference:url,doc.emergingthreats.net/2009099; classtype:policy-violation; sid:2009099; rev:4; metadata:created_at 2010_07_30, updated_at 2019_01_28;)
` 

Name : **ThunderNetwork UDP Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,xunlei.com|url,en.wikipedia.org/wiki/Xunlei|url,doc.emergingthreats.net/2009099

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-01-28

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008625
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Pando Client User-Agent Detected"; flow:established,to_server; content:"Pando/"; http_user_agent; metadata: former_category P2P; reference:url,doc.emergingthreats.net/bin/view/Main/2008625; classtype:policy-violation; sid:2008625; rev:7; metadata:created_at 2010_07_30, updated_at 2019_01_30;)
` 

Name : **Pando Client User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008625

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-01-30

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008113
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Tor Get Server Request"; flow:established,to_server; content:"/tor/server/"; http_uri; nocase; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2008113; classtype:policy-violation; sid:2008113; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Tor Get Server Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2008113

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008115
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Tor Get Status Request"; flow:established,to_server; content:"/tor/status/"; http_uri; nocase; reference:url,tor.eff.org; reference:url,doc.emergingthreats.net/2008115; classtype:policy-violation; sid:2008115; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Tor Get Status Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,tor.eff.org|url,doc.emergingthreats.net/2008115

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001188
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET P2P Soulseek"; flow: established; content:"slsknet"; reference:url,www.slsknet.org; reference:url,doc.emergingthreats.net/bin/view/Main/2001188; classtype:policy-violation; sid:2001188; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Soulseek** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.slsknet.org|url,doc.emergingthreats.net/bin/view/Main/2001188

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011712
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (FDM 3.x)"; flow:to_server,established; content:"FDM 3."; http_user_agent; depth:6; reference:url,www.freedownloadmanager.org; reference:url,doc.emergingthreats.net/2011712; classtype:policy-violation; sid:2011712; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Bittorrent P2P Client User-Agent (FDM 3.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.freedownloadmanager.org|url,doc.emergingthreats.net/2011712

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012247
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BTWebClient UA uTorrent in use"; flow:established,to_server; content:"BTWebClient"; http_user_agent; classtype:policy-violation; sid:2012247; rev:5; metadata:created_at 2011_01_27, updated_at 2019_09_27;)
` 

Name : **BTWebClient UA uTorrent in use** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-01-27

Last modified date : 2019-09-27

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011705
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (rTorrent)"; flow:to_server,established; content:"rtorrent/"; depth:9; http_user_agent; reference:url,libtorrent.rakshasa.no; reference:url,doc.emergingthreats.net/2011705; classtype:policy-violation; sid:2011705; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Bittorrent P2P Client User-Agent (rTorrent)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,libtorrent.rakshasa.no|url,doc.emergingthreats.net/2011705

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012390
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Libtorrent User-Agent"; flow:to_server,established; content:"libtorrent"; nocase; http_user_agent; metadata: former_category P2P; classtype:policy-violation; sid:2012390; rev:5; metadata:created_at 2011_02_27, updated_at 2019_09_27;)
` 

Name : **Libtorrent User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-27

Last modified date : 2019-09-27

Rev version : 5

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006375
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client HTTP Request "; flow:to_server,established; content:"/trackerphp/announce.php?"; http_uri; nocase; content:"?port="; http_uri; nocase; content:"&peer_id="; http_uri; reference:url,doc.emergingthreats.net/bin/view/Main/2006375; classtype:trojan-activity; sid:2006375; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Bittorrent P2P Client HTTP Request ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006375

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001035
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Morpheus Install"; flow: to_server,established; content:"/morpheus/morpheus.exe"; http_uri; nocase; reference:url,www.morpheus.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001035; classtype:policy-violation; sid:2001035; rev:10; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Morpheus Install** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.morpheus.com|url,doc.emergingthreats.net/bin/view/Main/2001035

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001036
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Morpheus Install ini Download"; flow: to_server,established; content:"/morpheus/morpheus_sm.ini"; http_uri; nocase; reference:url,www.morpheus.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001036; classtype:policy-violation; sid:2001036; rev:10; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Morpheus Install ini Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.morpheus.com|url,doc.emergingthreats.net/bin/view/Main/2001036

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001037
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Morpheus Update Request"; flow: to_server,established; content:"/gwebcache/gcache.asg?hostfile="; http_uri; nocase; reference:url,www.morpheus.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001037; classtype:policy-violation; sid:2001037; rev:10; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Morpheus Update Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.morpheus.com|url,doc.emergingthreats.net/bin/view/Main/2001037

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018532
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P zzima_loader"; flow:established, to_server; content: "GET"; http_method; content:"/zzima_loader/"; fast_pattern; http_uri; content:"zzima-nloader/ 1.0.3.1"; http_user_agent; depth:22; content:!"Referer|3a|"; http_header; reference:md5,810b4464785d8d007ca0c86c046ac0ef; classtype:trojan-activity; sid:2018532; rev:4; metadata:created_at 2014_06_05, updated_at 2019_10_07;)
` 

Name : **zzima_loader** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,810b4464785d8d007ca0c86c046ac0ef

CVE reference : Not defined

Creation date : 2014-06-05

Last modified date : 2019-10-07

Rev version : 4

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011232
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P p2p Related User-Agent (eChanblard)"; flow:to_server,established; content:"eChanblard"; http_user_agent; depth:10; isdataat:!1,relative; reference:url,doc.emergingthreats.net/2011232; classtype:trojan-activity; sid:2011232; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **p2p Related User-Agent (eChanblard)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2011232

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001059
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Ares traffic"; flow:established,to_server; content:"User-Agent|3a 20|Ares"; http_header; reference:url,www.aresgalaxy.org; reference:url,doc.emergingthreats.net/bin/view/Main/2001059; classtype:policy-violation; sid:2001059; rev:10; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Ares traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.aresgalaxy.org|url,doc.emergingthreats.net/bin/view/Main/2001059

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007799
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Azureus P2P Client User-Agent"; flow:to_server,established; content:"Azureus"; depth:7; http_user_agent; reference:url,doc.emergingthreats.net/bin/view/Main/2007799; classtype:policy-violation; sid:2007799; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Azureus P2P Client User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007799

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011713
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (BTSP)"; flow:to_server,established; content:"BTSP/"; depth:5; http_user_agent; reference:url,doc.emergingthreats.net/2011713; classtype:policy-violation; sid:2011713; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (BTSP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2011713

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011710
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (BitComet)"; flow:to_server,established; content:"BitComet/"; depth:9; http_user_agent; reference:url,www.bitcomet.com; reference:url,doc.emergingthreats.net/2011710; classtype:policy-violation; sid:2011710; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (BitComet)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.bitcomet.com|url,doc.emergingthreats.net/2011710

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011702
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (BitTornado)"; flow:to_server,established; content:"BitTornado/"; depth:11; http_user_agent; reference:url,www.bittornado.com; reference:url,doc.emergingthreats.net/2011702; classtype:policy-violation; sid:2011702; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (BitTornado)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.bittornado.com|url,doc.emergingthreats.net/2011702

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006372
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (Bittorrent/5.x.x)"; flow:to_server,established; content:"Bittorrent"; depth:10; http_user_agent; reference:url,doc.emergingthreats.net/bin/view/Main/2006372; classtype:trojan-activity; sid:2006372; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (Bittorrent/5.x.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006372

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011700
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (KTorrent/3.x.x)"; flow:to_server,established; content:"KTorrent/3"; depth:10; http_user_agent; reference:url,ktorrent.org; reference:url,doc.emergingthreats.net/2011700; classtype:policy-violation; sid:2011700; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (KTorrent/3.x.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,ktorrent.org|url,doc.emergingthreats.net/2011700

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011711
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Bittorrent P2P Client User-Agent (KTorrent 2.x)"; flow:to_server,established; content:"ktorrent/2"; depth:10; http_user_agent; reference:url,ktorrent.org; reference:url,doc.emergingthreats.net/2011711; classtype:policy-violation; sid:2011711; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bittorrent P2P Client User-Agent (KTorrent 2.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,ktorrent.org|url,doc.emergingthreats.net/2011711

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011707
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P Client User-Agent (Shareaza 2.x)"; flow:to_server,established; content:"Shareaza 2."; depth:11; http_user_agent; reference:url,shareaza.sourceforge.net; reference:url,doc.emergingthreats.net/2011707; classtype:policy-violation; sid:2011707; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Client User-Agent (Shareaza 2.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,shareaza.sourceforge.net|url,doc.emergingthreats.net/2011707

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006371
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P BearShare P2P Gnutella Client User-Agent (BearShare 6.x.x.x)"; flow:to_server,established; content:"BearShare"; depth:9; http_user_agent; reference:url,doc.emergingthreats.net/bin/view/Main/2006371; classtype:trojan-activity; sid:2006371; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **BearShare P2P Gnutella Client User-Agent (BearShare 6.x.x.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006371

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001808
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P LimeWire P2P Traffic"; flow:established; content:"LimeWire"; nocase; depth:8; http_user_agent; reference:url,www.limewire.com; reference:url,doc.emergingthreats.net/bin/view/Main/2001808; classtype:policy-violation; sid:2001808; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_15;)
` 

Name : **LimeWire P2P Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.limewire.com|url,doc.emergingthreats.net/bin/view/Main/2001808

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-15

Rev version : 9

Category : P2P

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028942
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET P2P FFTorrent P2P Client User-Agent (FFTorrent/x.x.x)"; flow:to_server,established; content:"FFTorrent/"; depth:10; http_user_agent; classtype:policy-violation; sid:2028942; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_11_05, updated_at 2019_11_05;)
` 

Name : **FFTorrent P2P Client User-Agent (FFTorrent/x.x.x)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-05

Last modified date : 2019-11-05

Rev version : 2

Category : P2P

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

