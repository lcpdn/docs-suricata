# 2008446
`#alert udp any 53 -> $DNS_SERVERS any (msg:"ET DNS Excessive DNS Responses with 1 or more RR's (100+ in 10 seconds) - possible Cache Poisoning Attempt"; byte_test:2,>,0,6; byte_test:2,>,0,10; threshold: type both, track by_src, count 100, seconds 10; reference:url,doc.emergingthreats.net/bin/view/Main/2008446; classtype:bad-unknown; sid:2008446; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Excessive DNS Responses with 1 or more RR's (100+ in 10 seconds) - possible Cache Poisoning Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008446

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008475
`#alert udp any 53 -> $HOME_NET any (msg:"ET DNS Query Responses with 3 RR's set (50+ in 2 seconds) - possible A RR Cache Poisoning Attempt"; content: "|81 80 00 01 00 01 00 01|"; offset: 2; depth:8; threshold: type both, track by_src, count 50, seconds 2; reference:url,infosec20.blogspot.com/2008/07/kaminsky-dns-cache-poisoning-poc.html; reference:url,doc.emergingthreats.net/bin/view/Main/2008475; classtype:bad-unknown; sid:2008475; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Query Responses with 3 RR's set (50+ in 2 seconds) - possible A RR Cache Poisoning Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,infosec20.blogspot.com/2008/07/kaminsky-dns-cache-poisoning-poc.html|url,doc.emergingthreats.net/bin/view/Main/2008475

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008447
`#alert udp any 53 -> $HOME_NET any (msg:"ET DNS Query Responses with 3 RR's set (50+ in 2 seconds) - possible NS RR Cache Poisoning Attempt"; content: "|85 00 00 01 00 01 00 01|"; offset: 2; depth:8; threshold: type both, track by_src,count 50, seconds 2; reference:url,infosec20.blogspot.com/2008/07/kaminsky-dns-cache-poisoning-poc.html; reference:url,doc.emergingthreats.net/bin/view/Main/2008447; classtype:bad-unknown; sid:2008447; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Query Responses with 3 RR's set (50+ in 2 seconds) - possible NS RR Cache Poisoning Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,infosec20.blogspot.com/2008/07/kaminsky-dns-cache-poisoning-poc.html|url,doc.emergingthreats.net/bin/view/Main/2008447

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101948
`alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS zone transfer UDP"; content:"|00 00 FC|"; offset:14; reference:cve,1999-0532; reference:nessus,10595; classtype:attempted-recon; sid:2101948; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **zone transfer UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,1999-0532|nessus,10595

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101616
`alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named version attempt"; content:"|07|version"; offset:12; nocase; content:"|04|bind|00|"; offset:12; nocase; reference:nessus,10028; classtype:attempted-recon; sid:2101616; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named version attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10028

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100252
`alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named iquery attempt"; content:"|09 80 00 00 00 01 00 00 00 00|"; depth:16; offset:2; reference:bugtraq,134; reference:cve,1999-0009; reference:url,www.rfc-editor.org/rfc/rfc1035.txt; classtype:attempted-recon; sid:2100252; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named iquery attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,134|cve,1999-0009|url,www.rfc-editor.org/rfc/rfc1035.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100256
`alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named authors attempt"; content:"|07|authors"; offset:12; nocase; content:"|04|bind|00|"; offset:12; nocase; reference:nessus,10728; classtype:attempted-recon; sid:2100256; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named authors attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10728

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103154
`#alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS UDP inverse query overflow"; byte_test:1,<,16,2; byte_test:1,&,8,2; isdataat:400; reference:bugtraq,134; reference:cve,1999-0009; classtype:attempted-admin; sid:2103154; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **UDP inverse query overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,134|cve,1999-0009

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001116
`#alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, Format error"; pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x81/"; reference:url,doc.emergingthreats.net/2001116; classtype:not-suspicious; sid:2001116; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Standard query response, Format error** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2001116

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001117
`#alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, Name Error"; pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x83/"; reference:url,doc.emergingthreats.net/2001117; classtype:not-suspicious; sid:2001117; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Standard query response, Name Error** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2001117

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001118
`#alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, Not Implemented"; pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x84/"; reference:url,doc.emergingthreats.net/2001118; classtype:not-suspicious; sid:2001118; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Standard query response, Not Implemented** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2001118

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001119
`#alert udp $DNS_SERVERS 53 -> any any (msg:"ET DNS Standard query response, Refused"; pcre:"/^..[\x81\x82\x83\x84\x85\x86\x87]\x85/"; reference:url,doc.emergingthreats.net/2001119; classtype:not-suspicious; sid:2001119; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Standard query response, Refused** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2001119

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008470
`#alert udp any 53 -> $HOME_NET any (msg:"ET DNS Excessive NXDOMAIN responses - Possible DNS Backscatter or Domain Generation Algorithm Lookups"; byte_test:1,&,128,2; byte_test:1,&,1,3; byte_test:1,&,2,3; threshold: type both, track by_src, count 50, seconds 10; reference:url,doc.emergingthreats.net/bin/view/Main/2008470; classtype:bad-unknown; sid:2008470; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Excessive NXDOMAIN responses - Possible DNS Backscatter or Domain Generation Algorithm Lookups** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008470

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100257
`alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named version attempt"; flow:to_server,established; content:"|07|version"; offset:12; nocase; content:"|04|bind|00|"; offset:12; nocase; reference:arachnids,278; reference:nessus,10028; classtype:attempted-recon; sid:2100257; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named version attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,278|nessus,10028

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103153
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS TCP inverse query overflow"; flow:to_server,established; byte_test:1,<,16,4; byte_test:1,&,8,4; isdataat:400; reference:bugtraq,134; reference:cve,1999-0009; classtype:attempted-admin; sid:2103153; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TCP inverse query overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,134|cve,1999-0009

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100255
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS zone transfer TCP"; flow:to_server,established; content:"|00 00 FC|"; offset:15; reference:arachnids,212; reference:cve,1999-0532; reference:nessus,10595; classtype:attempted-recon; sid:2100255; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **zone transfer TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,212|cve,1999-0532|nessus,10595

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100253
`#alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"GPL DNS SPOOF query response PTR with TTL of 1 min. and no authority"; content:"|85 80 00 01 00 01 00 00 00 00|"; content:"|C0 0C 00 0C 00 01 00 00 00|<|00 0F|"; classtype:bad-unknown; sid:2100253; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SPOOF query response PTR with TTL of 1 min. and no authority** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101435
`alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named authors attempt"; flow:to_server,established; content:"|07|authors"; offset:12; nocase; content:"|04|bind|00|"; offset:12; nocase; reference:arachnids,480; reference:nessus,10728; classtype:attempted-recon; sid:2101435; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named authors attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,480|nessus,10728

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100261
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named overflow attempt"; flow:to_server,established; content:"|CD 80 E8 D7 FF FF FF|/bin/sh"; reference:url,www.cert.org/advisories/CA-1998-05.html; classtype:attempted-admin; sid:2100261; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.cert.org/advisories/CA-1998-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100259
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS named overflow ADM"; flow:to_server,established; content:"thisissometempspaceforthesockinaddrinyeahyeahiknowthisislamebutanywaywhocareshorizongotitworkingsoalliscool"; reference:bugtraq,788; reference:cve,1999-0833; classtype:attempted-admin; sid:2100259; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **named overflow ADM** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,788|cve,1999-0833

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100254
`#alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"GPL DNS SPOOF query response with TTL of 1 min. and no authority"; content:"|81 80 00 01 00 01 00 00 00 00|"; content:"|C0 0C 00 01 00 01 00 00 00|<|00 04|"; classtype:bad-unknown; sid:2100254; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SPOOF query response with TTL of 1 min. and no authority** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100258
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS EXPLOIT named 8.2->8.2.1"; flow:to_server,established; content:"../../../"; reference:bugtraq,788; reference:cve,1999-0833; classtype:attempted-admin; sid:2100258; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **EXPLOIT named 8.2->8.2.1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,788|cve,1999-0833

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : DNS

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011407
`#alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS DNS Query for Suspicious .com.ru Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|03|com|02|ru|00|"; fast_pattern; nocase; distance:0; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; classtype:bad-unknown; sid:2011407; rev:3; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **DNS Query for Suspicious .com.ru Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011408
`#alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS DNS Query for Suspicious .com.cn Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|03|com|02|cn|00|"; fast_pattern; nocase; distance:0; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; classtype:bad-unknown; sid:2011408; rev:3; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **DNS Query for Suspicious .com.cn Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011411
`#alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS DNS Query for Suspicious .co.kr Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|02|co|02|kr|00|"; fast_pattern; nocase; distance:0; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; classtype:bad-unknown; sid:2011411; rev:3; metadata:created_at 2010_09_27, updated_at 2010_09_27;)
` 

Name : **DNS Query for Suspicious .co.kr Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2010-09-27

Rev version : 3

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016413
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - sinkhole.cert.pl 148.81.111.111"; content:"|00 01 00 01|"; content:"|00 04 94 51 6f 6f|"; distance:4; within:6; classtype:trojan-activity; sid:2016413; rev:4; metadata:created_at 2013_02_14, updated_at 2013_02_14;)
` 

Name : **Reply Sinkhole - sinkhole.cert.pl 148.81.111.111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-14

Last modified date : 2013-02-14

Rev version : 4

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016423
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - Georgia Tech (2)"; content:"|00 01 00 01|"; content:"|00 04 32 3e 0c 67|"; distance:4; within:6; reference:url,virustracker.info; classtype:trojan-activity; sid:2016423; rev:6; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - Georgia Tech (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,virustracker.info

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016422
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - Georgia Tech (1)"; content:"|00 01 00 01|"; content:"|00 04 c6 3d e3 06|"; distance:4; within:6; reference:url,virustracker.info; classtype:trojan-activity; sid:2016422; rev:5; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - Georgia Tech (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,virustracker.info

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016421
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - 1and1 Internet AG"; content:"|00 01 00 01|"; content:"|00 04 52 a5 19 d2|"; distance:4; within:6; reference:url,virustracker.info; classtype:trojan-activity; sid:2016421; rev:5; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - 1and1 Internet AG** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,virustracker.info

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016420
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - German Company"; content:"|00 01 00 01|"; content:"|00 04 52 a5 19 a7|"; distance:4; within:6; reference:url,virustracker.info; classtype:trojan-activity; sid:2016420; rev:5; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - German Company** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,virustracker.info

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016419
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - Zinkhole.org"; content:"|00 01 00 01|"; content:"|00 04 b0 1f 3e 4c|"; distance:4; within:6; classtype:trojan-activity; sid:2016419; rev:5; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - Zinkhole.org** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016418
`alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - Dr. Web"; content:"|00 01 00 01|"; content:"|00 04 5b e9 f4 6a|"; distance:4; within:6; reference:url,virustracker.info; classtype:trojan-activity; sid:2016418; rev:5; metadata:created_at 2013_02_16, updated_at 2013_02_16;)
` 

Name : **Reply Sinkhole - Dr. Web** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,virustracker.info

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2013-02-16

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018517
`alert udp any 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole FBI Zeus P2P 1 - 142.0.36.234"; content:"|00 01 00 01|"; content:"|00 04 8e 00 24 ea|"; distance:4; within:6; classtype:trojan-activity; sid:2018517; rev:1; metadata:created_at 2014_06_03, updated_at 2014_06_03;)
` 

Name : **Reply Sinkhole FBI Zeus P2P 1 - 142.0.36.234** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-06-03

Last modified date : 2014-06-03

Rev version : 1

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016591
`alert udp any 53 -> $HOME_NET any (msg:"ET DNS Reply Sinkhole - 106.187.96.49 blacklistthisdomain.com"; content:"|00 01 00 01|"; content:"|00 04 6a bb 60 31|"; distance:4; within:6; classtype:trojan-activity; sid:2016591; rev:6; metadata:created_at 2013_03_18, updated_at 2013_03_18;)
` 

Name : **Reply Sinkhole - 106.187.96.49 blacklistthisdomain.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-18

Last modified date : 2013-03-18

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013894
`alert udp any 53 -> $DNS_SERVERS any (msg:"ET DNS Excessive DNS Responses with 1 or more RR's (100+ in 10 seconds) to google.com.br possible Cache Poisoning Attempt"; byte_test:2,>,0,6; byte_test:2,>,0,10; threshold: type both, track by_src, count 100, seconds 10; content:"|06|google|03|com|02|br|00|"; reference:url,www.securelist.com/en/blog/208193214/Massive_DNS_poisoning_attacks_in_Brazil; reference:url,www.zdnet.com/blog/security/massive-dns-poisoning-attack-in-brazil-serving-exploits-and-malware/9780; classtype:bad-unknown; sid:2013894; rev:5; metadata:created_at 2011_11_10, updated_at 2011_11_10;)
` 

Name : **Excessive DNS Responses with 1 or more RR's (100+ in 10 seconds) to google.com.br possible Cache Poisoning Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.securelist.com/en/blog/208193214/Massive_DNS_poisoning_attacks_in_Brazil|url,www.zdnet.com/blog/security/massive-dns-poisoning-attack-in-brazil-serving-exploits-and-malware/9780

CVE reference : Not defined

Creation date : 2011-11-10

Last modified date : 2011-11-10

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014701
`alert udp $HOME_NET !9987 -> $EXTERNAL_NET 53 (msg:"ET DNS Non-DNS or Non-Compliant DNS traffic on DNS port Opcode 6 or 7 set"; content:!"7PYqwfzt"; depth:8; byte_test:1,!&,64,2; byte_test:1,&,32,2; byte_test:1,&,16,2; threshold: type limit, count 1, seconds 120, track by_dst; reference:md5,a56ec0f9bd46f921f65e4f6e598e5ed0; reference:url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html; classtype:policy-violation; sid:2014701; rev:12; metadata:created_at 2012_05_03, updated_at 2016_07_12;)
` 

Name : **Non-DNS or Non-Compliant DNS traffic on DNS port Opcode 6 or 7 set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,a56ec0f9bd46f921f65e4f6e598e5ed0|url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html

CVE reference : Not defined

Creation date : 2012-05-03

Last modified date : 2016-07-12

Rev version : 12

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014702
`alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS Non-DNS or Non-Compliant DNS traffic on DNS port Opcode 8 through 15 set"; content:!"7PYqwfzt"; depth:8; byte_test:1,&,64,2; threshold: type limit, count 1, seconds 120, track by_dst; reference:md5,a56ec0f9bd46f921f65e4f6e598e5ed0; reference:url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html; classtype:policy-violation; sid:2014702; rev:9; metadata:created_at 2012_05_03, updated_at 2016_07_12;)
` 

Name : **Non-DNS or Non-Compliant DNS traffic on DNS port Opcode 8 through 15 set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,a56ec0f9bd46f921f65e4f6e598e5ed0|url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html

CVE reference : Not defined

Creation date : 2012-05-03

Last modified date : 2016-07-12

Rev version : 9

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014703
`alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS Non-DNS or Non-Compliant DNS traffic on DNS port Reserved Bit Set"; content:!"7PYqwfzt"; depth:8; byte_test:1,&,64,3; threshold: type limit, count 1, seconds 120, track by_dst; reference:md5,a56ec0f9bd46f921f65e4f6e598e5ed0; reference:url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html; classtype:policy-violation; sid:2014703; rev:9; metadata:created_at 2012_05_03, updated_at 2016_07_12;)
` 

Name : **Non-DNS or Non-Compliant DNS traffic on DNS port Reserved Bit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,a56ec0f9bd46f921f65e4f6e598e5ed0|url,vrt-blog.snort.org/2008/08/checking-multiple-bits-in-flag-field_29.html

CVE reference : Not defined

Creation date : 2012-05-03

Last modified date : 2016-07-12

Rev version : 9

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016778
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query to a *.pw domain - Likely Hostile"; dns_query; content:".pw"; nocase; isdataat:!1,relative; content:!".u.pw"; isdataat:!1,relative; nocase;  classtype:bad-unknown; sid:2016778; rev:5; metadata:created_at 2013_04_19, updated_at 2019_09_28;)
` 

Name : **Query to a *.pw domain - Likely Hostile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-19

Last modified date : 2019-09-28

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014169
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for .su TLD (Soviet Union) Often Malware Related"; dns_query; content:".su"; nocase; isdataat:!1,relative; reference:url,www.abuse.ch/?p=3581; classtype:bad-unknown; sid:2014169; rev:2; metadata:created_at 2012_01_31, updated_at 2019_09_28;)
` 

Name : **Query for .su TLD (Soviet Union) Often Malware Related** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.abuse.ch/?p=3581

CVE reference : Not defined

Creation date : 2012-01-31

Last modified date : 2019-09-28

Rev version : 3

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023883
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query to a *.top domain - Likely Hostile"; dns_query; content:".top"; nocase; isdataat:!1,relative; threshold:type limit, track by_src, count 1, seconds 30; reference:url,www.symantec.com/connect/blogs/shady-tld-research-gdn-and-our-2016-wrap; reference:url,www.spamhaus.org/statistics/tlds/; classtype:bad-unknown; sid:2023883; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_02_07, updated_at 2019_09_28;)
` 

Name : **Query to a *.top domain - Likely Hostile** 

Attack target : Client_Endpoint

Description : This signature matches on a .top domain TLD.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/connect/blogs/shady-tld-research-gdn-and-our-2016-wrap|url,www.spamhaus.org/statistics/tlds/

CVE reference : Not defined

Creation date : 2017-02-07

Last modified date : 2019-09-28

Rev version : 3

Category : DNS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011410
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for Suspicious .cz.cc Domain"; dns_query; content:".cz.cc"; isdataat:!1,relative; nocase; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; classtype:bad-unknown; sid:2011410; rev:4; metadata:created_at 2010_09_27, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .cz.cc Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013172
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for a Suspicious *.cu.cc domain"; dns_query; content:".cu.cc"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013172; rev:3; metadata:created_at 2011_07_02, updated_at 2019_09_28;)
` 

Name : **DNS Query for a Suspicious *.cu.cc domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-02

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012956
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for a Suspicious *.co.tv domain"; dns_query; content:".co.tv"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012956; rev:4; metadata:created_at 2011_06_08, updated_at 2019_09_28;)
` 

Name : **DNS Query for a Suspicious *.co.tv domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2019-09-28

Rev version : 5

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025146
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .gr.com Domain (gr .com in DNS Lookup)"; dns_query; content:".gr.com"; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.domain.gr.com; classtype:bad-unknown; sid:2025146; rev:3; metadata:created_at 2017_12_12, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .gr.com Domain (gr .com in DNS Lookup)** 

Attack target : Not defined

Description : DNS query for dynamic domain provider .gr.com

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.domain.gr.com

CVE reference : Not defined

Creation date : 2017-12-12

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027367
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious shell .now .sh Domain"; dns_query; content:"shell.now.sh"; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,www.lacework.com/blog-attacks-exploiting-confluence; classtype:misc-attack; sid:2027367; rev:2; metadata:affected_product Linux, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_05_18, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious shell .now .sh Domain** 

Attack target : Client_Endpoint

Description : Signatures alerts on DNS query for shell.now.sh - a "Reserve Shell as a Service" tool - initially used for pen-tests, but also observed in malware

Tags : Not defined

Affected products : Linux

Alert Classtype : misc-attack

URL reference : url,www.lacework.com/blog-attacks-exploiting-confluence

CVE reference : Not defined

Creation date : 2019-05-18

Last modified date : 2019-09-28

Rev version : 3

Category : INFO

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027759
`#alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for .co TLD"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|02|co|00|"; distance:0; fast_pattern; metadata: former_category DNS; classtype:bad-unknown; sid:2027759; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, updated_at 2019_07_26;)
` 

Name : **Query for .co TLD** 

Attack target : Client_Endpoint

Description : Alerts on a DNS query to a specific, uncommon TLD.

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-26

Last modified date : 2019-07-26

Rev version : 2

Category : DNS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011911
`alert udp $HOME_NET any -> any 53 (msg:"ET DNS Hiloti DNS CnC Channel Successful Install Message"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|05|empty"; nocase; distance:0; content:"|0C|explorer_exe"; nocase; distance:0; metadata: former_category DNS; reference:url,sign.kaffenews.com/?p=104; reference:url,blog.fortinet.com/hiloti-the-botmaster-of-disguise/; classtype:bad-unknown; sid:2011911; rev:3; metadata:created_at 2010_11_09, updated_at 2019_08_29;)
` 

Name : **Hiloti DNS CnC Channel Successful Install Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : url,sign.kaffenews.com/?p=104|url,blog.fortinet.com/hiloti-the-botmaster-of-disguise/

CVE reference : Not defined

Creation date : 2010-11-09

Last modified date : 2019-08-29

Rev version : 3

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012115
`alert udp $HOME_NET any -> any 53 (msg:"ET DNS DNS Query for a Suspicious Malware Related Numerical .in Domain"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|02|in|00|"; fast_pattern; nocase; distance:0; pcre:"/\x00[0-9]{4,7}\x02in\x00/i"; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; reference:url,www.isc.sans.org/diary.html?storyid=10165; classtype:bad-unknown; sid:2012115; rev:7; metadata:created_at 2010_12_30, updated_at 2019_08_29;)
` 

Name : **DNS Query for a Suspicious Malware Related Numerical .in Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104|url,www.isc.sans.org/diary.html?storyid=10165

CVE reference : Not defined

Creation date : 2010-12-30

Last modified date : 2019-08-29

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012900
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for a Suspicious *.ae.am domain"; dns_query; content:".ae.am"; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012900; rev:5; metadata:created_at 2011_05_31, updated_at 2019_09_28;)
` 

Name : **DNS Query for a Suspicious *.ae.am domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012903
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for a Suspicious *.qc.cx domain"; dns_query; content:".qc.cx"; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012903; rev:5; metadata:created_at 2011_05_31, updated_at 2019_09_28;)
` 

Name : **DNS Query for a Suspicious *.qc.cx domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012811
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query to a .tk domain - Likely Hostile"; dns_query; content:".tk"; fast_pattern; nocase; isdataat:!1,relative; content:!"www.google.tk"; metadata: former_category DNS; classtype:bad-unknown; sid:2012811; rev:5; metadata:created_at 2011_05_15, updated_at 2019_09_28;)
` 

Name : **Query to a .tk domain - Likely Hostile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-15

Last modified date : 2019-09-28

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027757
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for .to TLD"; dns_query; content:".to"; isdataat:!1,relative; fast_pattern; metadata: former_category DNS; classtype:bad-unknown; sid:2027757; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, updated_at 2019_09_28;)
` 

Name : **Query for .to TLD** 

Attack target : Client_Endpoint

Description : Alerts on a DNS query for a suspicious .to domain.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-26

Last modified date : 2019-09-28

Rev version : 4

Category : DNS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027758
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for .cc TLD"; dns_query; content:".cc"; isdataat:!1,relative; fast_pattern; metadata: former_category DNS; classtype:bad-unknown; sid:2027758; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, updated_at 2019_09_28;)
` 

Name : **Query for .cc TLD** 

Attack target : Client_Endpoint

Description : Alerts on a DNS query for a suspicious .cc domain.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-26

Last modified date : 2019-09-28

Rev version : 4

Category : DNS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011802
`alert udp ![$SMTP_SERVERS,$DNS_SERVERS] any -> $DNS_SERVERS 53 (msg:"ET DNS DNS Lookup for localhost.DOMAIN.TLD"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|09|localhost"; fast_pattern; nocase; classtype:bad-unknown; sid:2011802; rev:5; metadata:created_at 2010_10_12, updated_at 2019_09_03;)
` 

Name : **DNS Lookup for localhost.DOMAIN.TLD** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2019-09-03

Rev version : 6

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012826
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query to a Suspicious *.vv.cc domain"; dns_query; content:".vv.cc"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012826; rev:3; metadata:created_at 2011_05_19, updated_at 2019_09_28;)
` 

Name : **DNS Query to a Suspicious *.vv.cc domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-19

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012901
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for a Suspicious *.noc.su domain"; dns_query; content:".noc.su"; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012901; rev:4; metadata:created_at 2011_05_31, updated_at 2019_09_03;)
` 

Name : **Query for a Suspicious *.noc.su domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2019-09-03

Rev version : 4

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013124
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for Suspicious .co.be Domain"; dns_query; content:".co.be"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013124; rev:5; metadata:created_at 2011_06_28, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .co.be Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-28

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013016
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for Illegal Drug Sales Site (SilkRoad)"; dns_query; content:"ianxz6zefk72ulzz.onion"; depth:22; classtype:policy-violation; sid:2013016; rev:4; metadata:created_at 2011_06_13, updated_at 2019_09_03;)
` 

Name : **DNS Query for Illegal Drug Sales Site (SilkRoad)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-13

Last modified date : 2019-09-03

Rev version : 4

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013847
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .net.tf Domain"; dns_query; content:".net.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013847; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .net.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013848
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .eu.tf Domain"; dns_query; content:".eu.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013848; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .eu.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013849
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .int.tf Domain"; dns_query; content:".int.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013849; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .int.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013850
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .edu.tf Domain"; dns_query; content:".edu.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013850; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .edu.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013851
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .us.tf Domain"; dns_query; content:".us.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013851; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .us.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013852
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .ca.tf Domain"; dns_query; content:".ca.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013852; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .ca.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013853
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .bg.tf Domain"; dns_query; content:".bg.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013853; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .bg.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013854
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .ru.tf Domain"; dns_query; content:".ru.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013854; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .ru.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013855
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .pl.tf Domain"; dns_query; content:".pl.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013855; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .pl.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013856
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .cz.tf Domain"; dns_query; content:".cz.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013856; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .cz.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013857
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .de.tf Domain"; dns_query; content:".de.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013857; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .de.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013858
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .at.tf Domain"; dns_query; content:".at.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013858; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .at.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013859
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .ch.tf Domain"; dns_query; content:".ch.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013859; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .ch.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013860
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .sg.tf Domain"; dns_query; content:".sg.tf"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013860; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .sg.tf Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013861
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .nl.ai Domain"; dns_query; content:".nl.ai"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013861; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .nl.ai Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013862
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .xe.cx Domain"; dns_query; content:".xe.cx"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013862; rev:3; metadata:created_at 2011_11_07, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .xe.cx Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-07

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013970
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for Suspicious .noip.cn Domain"; dns_query; content:".noip.cn"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2013970; rev:3; metadata:created_at 2011_11_28, updated_at 2019_09_28;)
` 

Name : **Query for Suspicious .noip.cn Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-28

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014285
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for Suspicious .ch.vu Domain"; dns_query; content:".ch.vu"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,google.com/safebrowsing/diagnostic?site=ch.vu; classtype:bad-unknown; sid:2014285; rev:6; metadata:created_at 2012_02_27, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .ch.vu Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,google.com/safebrowsing/diagnostic?site=ch.vu

CVE reference : Not defined

Creation date : 2012-02-27

Last modified date : 2019-09-28

Rev version : 7

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012902
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for a Suspicious *.be.ma domain"; dns_query; content:".be.ma"; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012902; rev:5; metadata:created_at 2011_05_31, updated_at 2019_09_28;)
` 

Name : **DNS Query for a Suspicious *.be.ma domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015550
`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for a Suspicious *.upas.su domain"; dns_query; content:".upas.su"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2015550; rev:3; metadata:created_at 2012_07_31, updated_at 2019_09_28;)
` 

Name : **Query for a Suspicious *.upas.su domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-31

Last modified date : 2019-09-28

Rev version : 4

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011409
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for Suspicious .co.cc Domain"; dns_query; content:".co.cc"; fast_pattern; nocase; isdataat:!1,relative; metadata: former_category HUNTING; reference:url,sign.kaffenews.com/?p=104; classtype:bad-unknown; sid:2011409; rev:5; metadata:created_at 2010_09_27, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious .co.cc Domain** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,sign.kaffenews.com/?p=104

CVE reference : Not defined

Creation date : 2010-09-27

Last modified date : 2019-09-28

Rev version : 6

Category : INFO

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018438
`alert dns $HOME_NET any -> any any (msg:"ET DNS DNS Query for vpnoverdns - indicates DNS tunnelling"; dns_query; content:"tun.vpnoverdns.com"; depth:18; fast_pattern; nocase; isdataat:!1,relative; reference:url,osint.bambenekconsulting.com/manual/vpnoverdns.txt; classtype:bad-unknown; sid:2018438; rev:4; metadata:created_at 2014_05_01, updated_at 2019_09_28;)
` 

Name : **DNS Query for vpnoverdns - indicates DNS tunnelling** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,osint.bambenekconsulting.com/manual/vpnoverdns.txt

CVE reference : Not defined

Creation date : 2014-05-01

Last modified date : 2019-09-28

Rev version : 5

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016569
`alert udp $HOME_NET any -> any 53 (msg:"ET DNS APT_NGO_wuaclt C2 Domain micorsofts.net"; content:"|0a|micorsofts|03|net|00|"; nocase; fast_pattern; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category DNS; reference:url,labs.alienvault.com; classtype:bad-unknown; sid:2016569; rev:4; metadata:created_at 2013_03_13, updated_at 2019_10_07;)
` 

Name : **APT_NGO_wuaclt C2 Domain micorsofts.net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : targeted-activity

URL reference : url,labs.alienvault.com

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2019-10-07

Rev version : 4

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016571
`alert udp $HOME_NET any -> any 53 (msg:"ET DNS APT_NGO_wuaclt C2 Domain hotmal1.com"; content:"|07|hotmal1|03|com|00|"; nocase; fast_pattern; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category DNS; reference:url,labs.alienvault.com; classtype:bad-unknown; sid:2016571; rev:2; metadata:created_at 2013_03_13, updated_at 2019_10_07;)
` 

Name : **APT_NGO_wuaclt C2 Domain hotmal1.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : targeted-activity

URL reference : url,labs.alienvault.com

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2019-10-07

Rev version : 2

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016570
`alert udp $HOME_NET any -> any 53 (msg:"ET DNS APT_NGO_wuaclt C2 Domain micorsofts.com"; content:"|0a|micorsofts|03|com|00|"; nocase; fast_pattern; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category DNS; reference:url,labs.alienvault.com; classtype:bad-unknown; sid:2016570; rev:3; metadata:created_at 2013_03_13, updated_at 2019_10_07;)
` 

Name : **APT_NGO_wuaclt C2 Domain micorsofts.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : targeted-activity

URL reference : url,labs.alienvault.com

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2019-10-07

Rev version : 3

Category : DNS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

