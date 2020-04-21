# 2001055
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 8000 (msg:"ET MISC HP Web JetAdmin ExecuteFile admin access"; flow: to_server,established; content:"/plugins/framework/script/content.hts"; nocase; content:"ExecuteFile"; nocase; reference:bugtraq,10224; reference:url,doc.emergingthreats.net/2001055; classtype:attempted-admin; sid:2001055; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HP Web JetAdmin ExecuteFile admin access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10224|url,doc.emergingthreats.net/2001055

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102008
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS invalid user authentication response"; flow:from_server,established; content:"E Fatal error, aborting."; content:"|3A| no such user"; classtype:misc-attack; sid:2102008; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS invalid user authentication response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102009
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS invalid repository response"; flow:from_server,established; content:"error "; content:"|3A| no such repository"; content:"I HATE YOU"; classtype:misc-attack; sid:2102009; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS invalid repository response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102010
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS double free exploit attempt response"; flow:from_server,established; content:"free|28 29 3A| warning|3A| chunk is already free"; reference:bugtraq,6650; reference:cve,2003-0015; classtype:misc-attack; sid:2102010; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS double free exploit attempt response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6650|cve,2003-0015

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102011
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS invalid directory response"; flow:from_server,established; content:"E protocol error|3A| invalid directory syntax in"; reference:bugtraq,6650; reference:cve,2003-0015; classtype:misc-attack; sid:2102011; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS invalid directory response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6650|cve,2003-0015

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102012
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS missing cvsroot response"; flow:from_server,established; content:"E protocol error|3A| Root request missing"; classtype:misc-attack; sid:2102012; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS missing cvsroot response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102013
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS invalid module response"; flow:from_server,established; content:"cvs server|3A| cannot find module"; content:"error"; distance:1; classtype:misc-attack; sid:2102013; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS invalid module response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101939
`#alert udp $EXTERNAL_NET any -> $HOME_NET 67 (msg:"GPL MISC bootp hardware address length overflow"; content:"|01|"; depth:1; byte_test:1,>,6,2; reference:cve,1999-0798; classtype:misc-activity; sid:2101939; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **bootp hardware address length overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : cve,1999-0798

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101940
`#alert udp $EXTERNAL_NET any -> $HOME_NET 67 (msg:"GPL MISC bootp invalid hardware type"; content:"|01|"; depth:1; byte_test:1,>,7,1; reference:cve,1999-0798; classtype:misc-activity; sid:2101940; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **bootp invalid hardware type** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : cve,1999-0798

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101917
`#alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"GPL MISC UPnP service discover attempt"; content:"M-SEARCH "; depth:9; content:"ssdp|3A|discover"; classtype:network-scan; sid:2101917; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **UPnP service discover attempt** 

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

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100449
`#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL MISC Time-To-Live Exceeded in Transit"; icode:0; itype:11; classtype:misc-activity; sid:2100449; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Time-To-Live Exceeded in Transit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101627
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC Unassigned/Reserved IP protocol"; ip_proto:>134; reference:url,www.iana.org/assignments/protocol-numbers; classtype:non-standard-protocol; sid:2101627; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Unassigned/Reserved IP protocol** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : non-standard-protocol

URL reference : url,www.iana.org/assignments/protocol-numbers

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100281
`#alert udp $EXTERNAL_NET any -> $HOME_NET 9 (msg:"GPL MISC Ascend Route"; content:"NAMENAME"; depth:50; offset:25; reference:bugtraq,714; reference:cve,1999-0060; classtype:attempted-dos; sid:2100281; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Ascend Route** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,714|cve,1999-0060

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100517
`#alert udp $EXTERNAL_NET any -> $HOME_NET 177 (msg:"GPL MISC xdmcp query"; content:"|00 01 00 03 00 01 00|"; classtype:attempted-recon; sid:2100517; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xdmcp query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101538
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC AUTHINFO USER overflow attempt"; flow:to_server,established; content:"AUTHINFO"; nocase; content:"USER"; distance:0; nocase; isdataat:200,relative; pcre:"/^AUTHINFO\s+USER\s[^\n]{200}/smi"; reference:arachnids,274; reference:bugtraq,1156; reference:cve,2000-0341; classtype:attempted-admin; sid:2101538; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AUTHINFO USER overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,274|bugtraq,1156|cve,2000-0341

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100523
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC ip reserved bit set"; fragbits:R; classtype:misc-activity; sid:2100523; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ip reserved bit set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100511
`alert tcp $HOME_NET 5631 -> $EXTERNAL_NET any (msg:"GPL MISC Invalid PCAnywhere Login"; flow:from_server,established; content:"Invalid login"; depth:13; offset:5; classtype:unsuccessful-user; sid:2100511; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Invalid PCAnywhere Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103078
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC nntp SEARCH pattern overflow attempt"; flow:to_server,established; content:"SEARCH"; nocase; pcre:"/^SEARCH\s+[^\n]{1024}/smi"; reference:cve,2004-0574; reference:url,www.microsoft.com/technet/security/bulletin/MS04-036.mspx; classtype:attempted-admin; sid:2103078; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **nntp SEARCH pattern overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2004-0574|url,www.microsoft.com/technet/security/bulletin/MS04-036.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100328
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL MISC Finger bomb attempt"; flow:to_server,established; content:"@@"; reference:arachnids,381; reference:cve,1999-0106; classtype:attempted-dos; sid:2100328; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger bomb attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : arachnids,381|cve,1999-0106

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100326
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL MISC Finger remote command execution attempt"; flow:to_server,established; content:"|3B|"; reference:arachnids,379; reference:bugtraq,974; reference:cve,1999-0150; classtype:attempted-user; sid:2100326; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger remote command execution attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,379|bugtraq,974|cve,1999-0150

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100327
`alert tcp $EXTERNAL_NET any -> $HOME_NET 79 (msg:"GPL MISC Finger remote command pipe execution attempt"; flow:to_server,established; content:"|7C|"; reference:arachnids,380; reference:bugtraq,2220; reference:cve,1999-0152; classtype:attempted-user; sid:2100327; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Finger remote command pipe execution attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,380|bugtraq,2220|cve,1999-0152

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102317
`alert tcp $HOME_NET 2401 -> $EXTERNAL_NET any (msg:"GPL MISC CVS non-relative path error response"; flow:from_server,established; content:"E cvs server|3A| warning|3A| cannot make directory CVS in /"; reference:bugtraq,9178; reference:cve,2003-0977; classtype:misc-attack; sid:2102317; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CVS non-relative path error response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9178|cve,2003-0977

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102189
`#alert ip any any -> any any (msg:"GPL MISC IP Proto 103 PIM"; ip_proto:103; reference:bugtraq,8211; reference:cve,2003-0567; classtype:non-standard-protocol; sid:2102189; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IP Proto 103 PIM** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : non-standard-protocol

URL reference : bugtraq,8211|cve,2003-0567

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102188
`#alert ip any any -> any any (msg:"GPL MISC IP Proto 77 Sun ND"; ip_proto:77; reference:bugtraq,8211; reference:cve,2003-0567; classtype:non-standard-protocol; sid:2102188; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IP Proto 77 Sun ND** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : non-standard-protocol

URL reference : bugtraq,8211|cve,2003-0567

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102187
`#alert ip any any -> any any (msg:"GPL MISC IP Proto 55 IP Mobility"; ip_proto:55; reference:bugtraq,8211; reference:cve,2003-0567; classtype:non-standard-protocol; sid:2102187; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IP Proto 55 IP Mobility** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : non-standard-protocol

URL reference : bugtraq,8211|cve,2003-0567

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102186
`#alert ip any any -> any any (msg:"GPL MISC IP Proto 53 SWIPE"; ip_proto:53; reference:bugtraq,8211; reference:cve,2003-0567; classtype:non-standard-protocol; sid:2102186; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IP Proto 53 SWIPE** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : non-standard-protocol

URL reference : bugtraq,8211|cve,2003-0567

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102159
`#alert tcp $EXTERNAL_NET any <> $HOME_NET 179 (msg:"GPL MISC BGP invalid type 0"; flow:stateless; content:"|FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF|"; depth:16; content:"|00|"; within:1; distance:2; reference:bugtraq,6213; reference:cve,2002-1350; classtype:bad-unknown; sid:2102159; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **BGP invalid type 0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,6213|cve,2002-1350

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102158
`#alert tcp any any <> any 179 (msg:"GPL MISC BGP invalid length"; flow:stateless; content:"|FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF|"; byte_test:2,<,19,0,relative; reference:bugtraq,6213; reference:cve,2002-1350; reference:url,sf.net/tracker/index.php?func=detail&aid=744523&group_id=53066&atid=469575; classtype:bad-unknown; sid:2102158; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **BGP invalid length** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,6213|cve,2002-1350|url,sf.net/tracker/index.php?func=detail&aid=744523&group_id=53066&atid=469575

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102048
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 873 (msg:"GPL MISC rsyncd overflow attempt"; flow:to_server; byte_test:2,>,4000,0; content:"|00 00|"; depth:2; offset:2; reference:bugtraq,9153; reference:cve,2003-0962; reference:nessus,11943; classtype:misc-activity; sid:2102048; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rsyncd overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : bugtraq,9153|cve,2003-0962|nessus,11943

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102523
`#alert tcp $EXTERNAL_NET any <> $HOME_NET 179 (msg:"GPL MISC BGP spoofed connection reset attempt"; flow:established; flags:RSF*; threshold:type both,track by_dst,count 10,seconds 10; metadata: former_category MISC; reference:bugtraq,10183; reference:cve,2004-0230; reference:url,www.uniras.gov.uk/vuls/2004/236929/index.htm; classtype:attempted-dos; sid:2102523; rev:8; metadata:created_at 2010_09_23, updated_at 2019_05_21;)
` 

Name : **BGP spoofed connection reset attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,10183|cve,2004-0230|url,www.uniras.gov.uk/vuls/2004/236929/index.htm

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-05-21

Rev version : 8

Category : DELETED

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102547
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC HP Web JetAdmin remote file upload attempt"; flow:to_server,established; content:"/plugins/hpjwja/script/devices_update_printer_fw_upload.hts"; http_uri; content:"Content-Type|3A|"; http_header; content:"Multipart"; distance:0; http_header; reference:bugtraq,9978; classtype:web-application-activity; sid:2102547; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **HP Web JetAdmin remote file upload attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,9978

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102548
`alert http $EXTERNAL_NET any -> $HOME_NET 8000 (msg:"GPL MISC HP Web JetAdmin setinfo access"; flow:to_server,established; content:"/plugins/hpjdwm/script/test/setinfo.hts"; nocase; http_uri; reference:bugtraq,9972; classtype:web-application-activity; sid:2102548; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **HP Web JetAdmin setinfo access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,9972

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102549
`alert tcp $EXTERNAL_NET any -> $HOME_NET 8000 (msg:"GPL MISC HP Web JetAdmin file write attempt"; flow:to_server,established; content:"/plugins/framework/script/tree.xms"; nocase; content:"WriteToFile"; nocase; reference:bugtraq,9973; classtype:web-application-activity; sid:2102549; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **HP Web JetAdmin file write attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,9973

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102561
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 873 (msg:"GPL MISC rsync backup-dir directory traversal attempt"; flow:to_server,established; content:"--backup-dir"; pcre:"/--backup-dir\s+\x2e\x2e\x2f/"; reference:bugtraq,10247; reference:cve,2004-0426; reference:nessus,12230; classtype:string-detect; sid:2102561; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rsync backup-dir directory traversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : bugtraq,10247|cve,2004-0426|nessus,12230

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101792
`#alert tcp $EXTERNAL_NET 119 -> $HOME_NET any (msg:"GPL MISC return code buffer overflow attempt"; flow:to_client,established,no_stream; content:"200"; isdataat:64,relative; pcre:"/^200\s[^\n]{64}/smi"; reference:bugtraq,4900; reference:cve,2002-0909; classtype:protocol-command-decode; sid:2101792; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **return code buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,4900|cve,2002-0909

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101388
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"GPL MISC UPnP Location overflow"; content:"Location|3A|"; nocase; isdataat:128,relative; pcre:"/^Location\x3a[^\n]{128}/smi"; reference:bugtraq,3723; reference:cve,2001-0876; classtype:misc-attack; sid:2101388; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **UPnP Location overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,3723|cve,2001-0876

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101384
`alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"GPL MISC UPnP malformed advertisement"; content:"NOTIFY * "; nocase; reference:bugtraq,3723; reference:cve,2001-0876; reference:cve,2001-0877; reference:url,www.microsoft.com/technet/security/bulletin/MS01-059.mspx; classtype:misc-attack; sid:2101384; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **UPnP malformed advertisement** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,3723|cve,2001-0876|cve,2001-0877|url,www.microsoft.com/technet/security/bulletin/MS01-059.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103089
`#alert udp $EXTERNAL_NET any -> $HOME_NET 2048 (msg:"GPL MISC squid WCCP I_SEE_YOU message overflow attempt"; content:"|00 00 00 08|"; depth:4; byte_test:4,>,32,16; reference:bugtraq,12275; reference:cve,2005-0095; classtype:attempted-user; sid:2103089; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **squid WCCP I_SEE_YOU message overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,12275|cve,2005-0095

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101323
`alert tcp $EXTERNAL_NET any -> $HOME_NET 4321 (msg:"GPL MISC rwhoisd format string attempt"; flow:to_server,established; content:"-soa %p"; reference:bugtraq,3474; reference:cve,2001-0838; classtype:misc-attack; sid:2101323; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rwhoisd format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,3474|cve,2001-0838

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102430
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP newgroup overflow attempt"; flow:to_server,established; content:"newgroup"; nocase; isdataat:21,relative; pcre:"/^newgroup\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102430; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP newgroup overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100608
`alert tcp $EXTERNAL_NET any -> $HOME_NET 514 (msg:"GPL MISC rsh echo + +"; flow:to_server,established; content:"echo |22|+ +|22|"; reference:arachnids,388; classtype:attempted-user; sid:2100608; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rsh echo + +** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,388

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102927
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP XPAT pattern overflow attempt"; flow:to_server,established; content:"PAT"; nocase; isdataat:1024,relative; pcre:"/^X?PAT\s+[^\n]{1024}/smi"; reference:cve,2004-0574; reference:url,www.microsoft.com/technet/security/bulletin/MS04-036.mspx; classtype:attempted-admin; sid:2102927; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP XPAT pattern overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2004-0574|url,www.microsoft.com/technet/security/bulletin/MS04-036.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100488
`#alert tcp $EXTERNAL_NET 80 -> $HOME_NET any (msg:"GPL MISC Connection Closed MSG from Port 80"; flow:from_server,established; content:"Connection closed by foreign host"; nocase; classtype:unknown; sid:2100488; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Connection Closed MSG from Port 80** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100270
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC Teardrop attack"; fragbits:M; id:242; reference:bugtraq,124; reference:cve,1999-0015; reference:nessus,10279; reference:url,www.cert.org/advisories/CA-1997-28.html; classtype:attempted-dos; sid:2100270; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Teardrop attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,124|cve,1999-0015|nessus,10279|url,www.cert.org/advisories/CA-1997-28.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101321
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC 0 ttl"; ttl:0; reference:url,support.microsoft.com/default.aspx?scid=kb#-#-EN-US#-#-q138268; reference:url,www.isi.edu/in-notes/rfc1122.txt; classtype:misc-activity; sid:2101321; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **0 ttl** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,support.microsoft.com/default.aspx?scid=kb#-#-EN-US#-#-q138268|url,www.isi.edu/in-notes/rfc1122.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102424
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP sendsys overflow attempt"; flow:to_server,established; content:"sendsys"; nocase; pcre:"/^sendsys\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102424; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP sendsys overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100502
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL MISC source route ssrr"; ipopts:ssrr ; reference:arachnids,422; classtype:bad-unknown; sid:2100502; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **source route ssrr** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,422

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100616
`alert tcp $EXTERNAL_NET any -> $HOME_NET 113 (msg:"GPL MISC ident version request"; flow:to_server,established; content:"VERSION|0A|"; depth:16; reference:arachnids,303; classtype:attempted-recon; sid:2100616; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ident version request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,303

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102432
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP article post without path attempt"; flow:to_server,established; content:"takethis"; nocase; pcre:!"/^takethis.*?Path\x3a.*?[\r]{0,1}?\n[\r]{0,1}\n/si"; classtype:attempted-admin; sid:2102432; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP article post without path attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102427
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP checkgroups overflow attempt"; flow:to_server,established; content:"checkgroups"; nocase; pcre:"/^checkgroups\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102427; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP checkgroups overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102428
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP ihave overflow attempt"; flow:to_server,established; content:"ihave"; nocase; pcre:"/^ihave\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102428; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP ihave overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102431
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC Nntp rmgroup overflow attempt"; flow:to_server,established; content:"rmgroup"; nocase; pcre:"/^rmgroup\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102431; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Nntp rmgroup overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102429
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP sendme overflow attempt"; flow:to_server,established; content:"sendme"; nocase; pcre:"/^sendme\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102429; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP sendme overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102425
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP senduuname overflow attempt"; flow:to_server,established; content:"senduuname"; nocase; pcre:"/^senduuname\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102425; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP senduuname overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102426
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 119 (msg:"GPL MISC NNTP version overflow attempt"; flow:to_server,established; content:"version"; nocase; pcre:"/^version\x3a[^\n]{21}/smi"; reference:bugtraq,9382; reference:cve,2004-0045; classtype:attempted-admin; sid:2102426; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NNTP version overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9382|cve,2004-0045

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100602
`alert tcp $EXTERNAL_NET any -> $HOME_NET 513 (msg:"GPL MISC rlogin bin"; flow:to_server,established; content:"bin|00|bin|00|"; reference:arachnids,384; classtype:attempted-user; sid:2100602; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin bin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,384

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100603
`alert tcp $EXTERNAL_NET any -> $HOME_NET 513 (msg:"GPL MISC rlogin echo++"; flow:to_server,established; content:"echo |22| + + |22|"; reference:arachnids,385; classtype:bad-unknown; sid:2100603; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin echo++** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,385

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100606
`alert tcp $EXTERNAL_NET any -> $HOME_NET 513 (msg:"GPL MISC rlogin root"; flow:to_server,established; content:"root|00|root|00|"; reference:arachnids,389; classtype:attempted-admin; sid:2100606; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin root** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,389

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100609
`alert tcp $EXTERNAL_NET any -> $HOME_NET 514 (msg:"GPL MISC rsh froot"; flow:to_server,established; content:"-froot|00|"; reference:arachnids,387; classtype:attempted-admin; sid:2100609; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rsh froot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,387

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100610
`alert tcp $EXTERNAL_NET any -> $HOME_NET 514 (msg:"GPL MISC rsh root"; flow:to_server,established; content:"root|00|root|00|"; reference:arachnids,391; classtype:attempted-admin; sid:2100610; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rsh root** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,391

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014646
`#alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET MISC RuggedCom factory account backdoor"; flow:to_client,established;flowbits:isset,ET.RUGGED.BANNER; content:"Enter User Name|3A|"; pcre:"/Enter User Name\x3a(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*\s*(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*f(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*a(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*c(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*t(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*o(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*r(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*y(\xff[\xf0-\xff](\xff|[\x00-\x22]))*\x00*\x7f*\x08*[\r\n]/"; reference:url,www.exploit-db.com/exploits/18779/; reference:url,arstechnica.com/business/news/2012/04/backdoor-in-mission-critical-hardware-threatens-power-traffic-control-systems.ars; classtype:attempted-admin; sid:2014646; rev:4; metadata:created_at 2012_04_27, updated_at 2012_04_27;)
` 

Name : **RuggedCom factory account backdoor** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.exploit-db.com/exploits/18779/|url,arstechnica.com/business/news/2012/04/backdoor-in-mission-critical-hardware-threatens-power-traffic-control-systems.ars

CVE reference : Not defined

Creation date : 2012-04-27

Last modified date : 2012-04-27

Rev version : 4

Category : MISC

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100503
`#alert tcp $EXTERNAL_NET 20 -> $HOME_NET :1023 (msg:"GPL MISC Source Port 20 to <1024"; flow:to_server; flags:S,12; reference:arachnids,06; classtype:bad-unknown; sid:2100503; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Source Port 20 to <1024** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,06

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100504
`#alert tcp $EXTERNAL_NET 53 -> $HOME_NET :1023 (msg:"GPL MISC source port 53 to <1024"; flow:to_server; flags:S,12; reference:arachnids,07; classtype:bad-unknown; sid:2100504; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **source port 53 to <1024** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,07

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : MISC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

