# 2102005
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap kcms_server request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87|}"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,6665; reference:cve,2003-0027; reference:url,www.kb.cert.org/vuls/id/850785; classtype:rpc-portmap-decode; sid:2102005; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap kcms_server request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,6665|cve,2003-0027|url,www.kb.cert.org/vuls/id/850785

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102006
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap kcms_server request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87|}"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,6665; reference:cve,2003-0027; reference:url,www.kb.cert.org/vuls/id/850785; classtype:rpc-portmap-decode; sid:2102006; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap kcms_server request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,6665|cve,2003-0027|url,www.kb.cert.org/vuls/id/850785

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102007
`alert tcp $EXTERNAL_NET any -> $HOME_NET 32771:34000 (msg:"GPL RPC kcms_server directory traversal attempt"; flow:to_server,established; content:"|00 01 87|}"; depth:4; offset:16; byte_jump:4,20,relative,align; byte_jump:4,4,relative,align; content:"/../"; distance:0; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,6665; reference:cve,2003-0027; reference:url,www.kb.cert.org/vuls/id/850785; classtype:misc-attack; sid:2102007; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **kcms_server directory traversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6665|cve,2003-0027|url,www.kb.cert.org/vuls/id/850785

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102014
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap UNSET attempt TCP 111"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 02|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,1892; classtype:rpc-portmap-decode; sid:2102014; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap UNSET attempt TCP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,1892

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102015
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap UNSET attempt UDP 111"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 02|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,1892; classtype:rpc-portmap-decode; sid:2102015; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap UNSET attempt UDP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,1892

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102016
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap status request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B8|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,15; classtype:rpc-portmap-decode; sid:2102016; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap status request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,15

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102017
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap espd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 05 F7|u"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2714; reference:cve,2001-0331; classtype:rpc-portmap-decode; sid:2102017; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap espd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2714|cve,2001-0331

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102018
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP dump request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 02|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:attempted-recon; sid:2102018; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP dump request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102019
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP dump request"; content:"|00 01 86 A5|"; depth:4; offset:12; content:"|00 00 00 02|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:attempted-recon; sid:2102019; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP dump request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102020
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP unmount request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:attempted-recon; sid:2102020; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP unmount request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102021
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP unmount request"; content:"|00 01 86 A5|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:attempted-recon; sid:2102021; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP unmount request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102022
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP unmountall request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 04|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:attempted-recon; sid:2102022; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP unmountall request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102025
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd username overflow attempt UDP"; content:"|00 01 86 A9|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,0,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102025; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd username overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102026
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd username overflow attempt TCP"; flow:to_server,established; content:"|00 01 86 A9|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,0,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102026; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd username overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101950
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap SET attempt UDP 111"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101950; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap SET attempt UDP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101951
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP mount request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:attempted-recon; sid:2101951; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP mount request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101952
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP mount request"; content:"|00 01 86 A5|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:attempted-recon; sid:2101952; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP mount request** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101957
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC sadmind UDP PING"; content:"|00 01 87 88|"; depth:4; offset:12; content:"|00 00 00 00|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,866; classtype:attempted-admin; sid:2101957; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sadmind UDP PING** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,866

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101958
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC sadmind TCP PING"; flow:to_server,established; content:"|00 01 87 88|"; depth:4; offset:16; content:"|00 00 00 00|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,866; classtype:attempted-admin; sid:2101958; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sadmind TCP PING** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,866

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101959
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap NFS request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A3|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101959; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap NFS request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101960
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap NFS request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A3|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2101960; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap NFS request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101961
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap RQUOTA request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 AB|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101961; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap RQUOTA request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101962
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap RQUOTA request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 AB|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2101962; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap RQUOTA request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101963
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC RQUOTA getquota overflow attempt UDP"; content:"|00 01 86 AB|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,128,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,864; reference:cve,1999-0974; classtype:misc-attack; sid:2101963; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RQUOTA getquota overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,864|cve,1999-0974

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101964
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC tooltalk UDP overflow attempt"; content:"|00 01 86 F3|"; depth:4; offset:12; content:"|00 00 00 07|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,128,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,122; reference:cve,1999-0003; classtype:misc-attack; sid:2101964; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **tooltalk UDP overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,122|cve,1999-0003

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101965
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC tooltalk TCP overflow attempt"; flow:to_server,established; content:"|00 01 86 F3|"; depth:4; offset:16; content:"|00 00 00 07|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,128,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,122; reference:cve,1999-0003; classtype:misc-attack; sid:2101965; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **tooltalk TCP overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,122|cve,1999-0003

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101949
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap SET attempt TCP 111"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2101949; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap SET attempt TCP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101922
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap proxy attempt TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 05|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2101922; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap proxy attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101923
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap proxy attempt UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 05|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101923; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap proxy attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101925
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP exportall request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 06|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,26; classtype:attempted-recon; sid:2101925; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP exportall request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,26

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101907
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC CMSD UDP CMSD_CREATE buffer overflow attempt"; content:"|00 01 86 E4|"; depth:4; offset:12; content:"|00 00 00 15|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1024,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,524; reference:cve,1999-0696; classtype:attempted-admin; sid:2101907; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMSD UDP CMSD_CREATE buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,524|cve,1999-0696

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101908
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC CMSD TCP CMSD_CREATE buffer overflow attempt"; flow:to_server,established; content:"|00 01 86 E4|"; depth:4; offset:16; content:"|00 00 00 15|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1024,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,524; reference:cve,1999-0696; classtype:attempted-admin; sid:2101908; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMSD TCP CMSD_CREATE buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,524|cve,1999-0696

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101909
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC CMSD TCP CMSD_INSERT buffer overflow attempt"; flow:to_server,established; content:"|00 01 86 E4|"; depth:4; offset:16; content:"|00 00 00 06|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,0,relative,align; byte_test:4,>,1000,28,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,524; reference:cve,1999-0696; reference:url,www.cert.org/advisories/CA-99-08-cmsd.html; classtype:misc-attack; sid:2101909; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMSD TCP CMSD_INSERT buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,524|cve,1999-0696|url,www.cert.org/advisories/CA-99-08-cmsd.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101912
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC sadmind TCP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt"; flow:to_server,established; content:"|00 01 87 88|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,124,relative,align; byte_jump:4,20,relative,align; byte_test:4,>,512,4,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,0866; reference:bugtraq,866; reference:cve,1999-0977; classtype:attempted-admin; sid:2101912; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sadmind TCP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,0866|bugtraq,866|cve,1999-0977

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101913
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC STATD UDP stat mon_name format string exploit attempt"; content:"|00 01 86 B8|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,100,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,1480; reference:cve,2000-0666; classtype:attempted-admin; sid:2101913; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STATD UDP stat mon_name format string exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1480|cve,2000-0666

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101914
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC STATD TCP stat mon_name format string exploit attempt"; flow:to_server,established; content:"|00 01 86 B8|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,100,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,1480; reference:cve,2000-0666; classtype:attempted-admin; sid:2101914; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STATD TCP stat mon_name format string exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1480|cve,2000-0666

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101915
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC STATD UDP monitor mon_name format string exploit attempt"; content:"|00 01 86 B8|"; depth:4; offset:12; content:"|00 00 00 02|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,100,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,1480; reference:cve,2000-0666; classtype:attempted-admin; sid:2101915; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STATD UDP monitor mon_name format string exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1480|cve,2000-0666

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101916
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC STATD TCP monitor mon_name format string exploit attempt"; flow:to_server,established; content:"|00 01 86 B8|"; depth:4; offset:16; content:"|00 00 00 02|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,100,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,1480; reference:cve,2000-0666; classtype:attempted-admin; sid:2101916; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STATD TCP monitor mon_name format string exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1480|cve,2000-0666

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101891
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 1024: (msg:"GPL RPC status GHBN format string attack"; flow:to_server, established; content:"|00 01 86 B8|"; depth:4; offset:16; content:"|00 00 00 02|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"%x %x"; within:256; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,1480; reference:cve,2000-0666; classtype:misc-attack; sid:2101891; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **status GHBN format string attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1480|cve,2000-0666

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101867
`alert udp $EXTERNAL_NET any -> $HOME_NET 177 (msg:"GPL RPC xdmcp info query"; content:"|00 01 00 02 00 01 00|"; reference:nessus,10891; classtype:attempted-recon; sid:2101867; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xdmcp info query** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : nessus,10891

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101746
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap cachefsd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 8B|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,4674; reference:cve,2002-0033; reference:cve,2002-0084; classtype:rpc-portmap-decode; sid:2101746; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap cachefsd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,4674|cve,2002-0033|cve,2002-0084

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101747
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap cachefsd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 8B|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,4674; reference:cve,2002-0033; reference:cve,2002-0084; classtype:rpc-portmap-decode; sid:2101747; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap cachefsd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,4674|cve,2002-0033|cve,2002-0084

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101732
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rwalld request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A8|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101732; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rwalld request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101733
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rwalld request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A8|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2101733; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rwalld request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101926
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP exportall request"; content:"|00 01 86 A5|"; depth:4; offset:12; content:"|00 00 00 06|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:attempted-recon; sid:2101926; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP exportall request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101924
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP export request"; content:"|00 01 86 A5|"; depth:4; offset:12; content:"|00 00 00 05|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:attempted-recon; sid:2101924; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP export request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101281
`#alert udp $EXTERNAL_NET any -> $HOME_NET 32771 (msg:"GPL RPC portmap listing UDP 32771"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 04|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101281; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap listing UDP 32771** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101277
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ypupdated request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 BC|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101277; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ypupdated request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102256
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC sadmind query with root credentials attempt UDP"; content:"|00 01 87 88|"; fast_pattern; depth:4; offset:12; content:"|00 00 00 01 00 00 00 01|"; within:8; distance:4; byte_jump:4,8,relative,align; content:"|00 00 00 00|"; within:4; classtype:misc-attack; sid:2102256; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sadmind query with root credentials attempt UDP** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102255
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC sadmind query with root credentials attempt TCP"; flow:to_server,established; content:"|00 01 87 88|"; fast_pattern; depth:4; offset:16; content:"|00 00 00 01 00 00 00 01|"; within:8; distance:4; byte_jump:4,8,relative,align; content:"|00 00 00 00|"; within:4; classtype:misc-attack; sid:2102255; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sadmind query with root credentials attempt TCP** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102185
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd UDP mount path overflow attempt"; content:"|00 01 86 A5 00|"; depth:5; offset:12; content:"|00 00 00 01|"; within:4; distance:3; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1023,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,8179; reference:cve,2003-0252; reference:nessus,11800; classtype:misc-attack; sid:2102185; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd UDP mount path overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,8179|cve,2003-0252|nessus,11800

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102184
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP mount path overflow attempt"; flow:to_server,established; content:"|00 01 86 A5 00|"; depth:5; offset:16; content:"|00 00 00 01|"; within:4; distance:3; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1023,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,8179; reference:cve,2003-0252; reference:nessus,11800; classtype:misc-attack; sid:2102184; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP mount path overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,8179|cve,2003-0252|nessus,11800

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102114
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 512 (msg:"GPL RPC rexec password overflow attempt"; flow:to_server,established; content:"|00|"; content:"|00|"; distance:33; content:"|00|"; distance:0; classtype:attempted-admin; sid:2102114; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rexec password overflow attempt** 

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

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102104
`alert tcp $HOME_NET 512 -> $EXTERNAL_NET any (msg:"GPL RPC rexec username too long response"; flow:from_server,established; content:"username too long"; depth:17; reference:bugtraq,7459; classtype:unsuccessful-user; sid:2102104; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rexec username too long response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : bugtraq,7459

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102095
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC CMSD TCP CMSD_CREATE array buffer overflow attempt"; flow:to_server,established; content:"|00 01 86 E4|"; depth:4; offset:16; content:"|00 00 00 15|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1024,20,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,5356; reference:cve,2002-0391; classtype:attempted-admin; sid:2102095; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMSD TCP CMSD_CREATE array buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,5356|cve,2002-0391

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102094
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC CMSD UDP CMSD_CREATE array buffer overflow attempt"; content:"|00 01 86 E4|"; depth:4; offset:12; content:"|00 00 00 15|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1024,20,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,5356; reference:cve,2002-0391; classtype:attempted-admin; sid:2102094; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMSD UDP CMSD_CREATE array buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,5356|cve,2002-0391

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102093
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap proxy integer overflow attempt TCP"; flow:to_server,established; content:"|00 01 86 A0 00|"; depth:5; offset:16; content:"|00 00 00 05|"; within:4; distance:3; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,2048,12,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,7123; reference:cve,2003-0028; classtype:rpc-portmap-decode; sid:2102093; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap proxy integer overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,7123|cve,2003-0028

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102088
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC ypupdated arbitrary command attempt UDP"; content:"|00 01 86 BC|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|7C|"; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:misc-attack; sid:2102088; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ypupdated arbitrary command attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102084
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC rpc.xfsmd xfs_export attempt TCP"; flow:to_server,established; content:"|00 05 F7|h"; depth:4; offset:16; content:"|00 00 00 0D|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,5072; reference:bugtraq,5075; reference:cve,2002-0359; classtype:rpc-portmap-decode; sid:2102084; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rpc.xfsmd xfs_export attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,5072|bugtraq,5075|cve,2002-0359

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102083
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC rpc.xfsmd xfs_export attempt UDP"; content:"|00 05 F7|h"; depth:4; offset:12; content:"|00 00 00 0D|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,5072; reference:bugtraq,5075; reference:cve,2002-0359; classtype:rpc-portmap-decode; sid:2102083; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rpc.xfsmd xfs_export attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,5072|bugtraq,5075|cve,2002-0359

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102082
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rpc.xfsmd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 05 F7|h"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,5072; reference:bugtraq,5075; reference:cve,2002-0359; classtype:rpc-portmap-decode; sid:2102082; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rpc.xfsmd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,5072|bugtraq,5075|cve,2002-0359

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102081
`#alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rpc.xfsmd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 05 F7|h"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,5072; reference:bugtraq,5075; reference:cve,2002-0359; classtype:rpc-portmap-decode; sid:2102081; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rpc.xfsmd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,5072|bugtraq,5075|cve,2002-0359

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102080
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap nlockmgr request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B5|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,1372; reference:cve,2000-0508; classtype:rpc-portmap-decode; sid:2102080; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap nlockmgr request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,1372|cve,2000-0508

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102079
`#alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap nlockmgr request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B5|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,1372; reference:cve,2000-0508; classtype:rpc-portmap-decode; sid:2102079; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap nlockmgr request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,1372|cve,2000-0508

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102036
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap network-status-monitor request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 03 0D|p"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; classtype:rpc-portmap-decode; sid:2102036; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap network-status-monitor request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102035
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap network-status-monitor request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 03 0D|p"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2102035; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap network-status-monitor request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102033
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC ypserv maplist request UDP"; content:"|00 01 86 A4|"; depth:4; offset:12; content:"|00 00 00 0B|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,5914; reference:bugtraq,6016; reference:cve,2002-1232; classtype:rpc-portmap-decode; sid:2102033; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ypserv maplist request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,5914|bugtraq,6016|cve,2002-1232

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102032
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd user update TCP"; flow:to_server,established; content:"|00 01 86 A9|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102032; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd user update TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102031
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd user update UDP"; content:"|00 01 86 A9|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102031; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd user update UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102030
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd new password overflow attempt TCP"; flow:to_server,established; content:"|00 01 86 A9|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,0,relative,align; byte_jump:4,0,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102030; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd new password overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102029
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd new password overflow attempt UDP"; content:"|00 01 86 A9|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_jump:4,0,relative,align; byte_jump:4,0,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102029; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd new password overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102028
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd old password overflow attempt TCP"; flow:to_server,established; content:"|00 01 86 A9|"; depth:4; offset:16; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102028; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd old password overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102027
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC yppasswd old password overflow attempt UDP"; content:"|00 01 86 A9|"; depth:4; offset:12; content:"|00 00 00 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,64,0,relative; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2763; reference:cve,2001-0779; classtype:rpc-portmap-decode; sid:2102027; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **yppasswd old password overflow attempt UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2763|cve,2001-0779

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102578
`#alert udp $EXTERNAL_NET any -> $HOME_NET 88 (msg:"GPL RPC kerberos principal name overflow UDP"; content:"j"; depth:1; content:"|01 A1|"; asn1:oversize_length 1024,relative_offset -1; reference:url,web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-005-buf.txt; classtype:attempted-admin; sid:2102578; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **kerberos principal name overflow UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-005-buf.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102579
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 88 (msg:"GPL RPC kerberos principal name overflow TCP"; flow:to_server,established; content:"j"; depth:1; offset:4; content:"|01 A1|"; asn1:oversize_length 1024,relative_offset -1; reference:url,web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-005-buf.txt; classtype:attempted-admin; sid:2102579; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **kerberos principal name overflow TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-005-buf.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101274
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ttdbserv request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 F3|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,24; reference:bugtraq,122; reference:bugtraq,3382; reference:cve,1999-0003; reference:cve,1999-0687; reference:cve,1999-1075; reference:cve,2001-0717; reference:url,www.cert.org/advisories/CA-2001-05.html; classtype:rpc-portmap-decode; sid:2101274; rev:19; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ttdbserv request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,24|bugtraq,122|bugtraq,3382|cve,1999-0003|cve,1999-0687|cve,1999-1075|cve,2001-0717|url,www.cert.org/advisories/CA-2001-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 19

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100569
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC snmpXdmi overflow attempt TCP"; flow:to_server,established; content:"|00 01 87 99|"; depth:4; offset:16; content:"|00 00 01 01|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; byte_test:4,>,1024,20,relative; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2417; reference:cve,2001-0236; reference:url,www.cert.org/advisories/CA-2001-05.html; classtype:attempted-admin; sid:2100569; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **snmpXdmi overflow attempt TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2417|cve,2001-0236|url,www.cert.org/advisories/CA-2001-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100585
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap sadmind request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 88|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,20; classtype:rpc-portmap-decode; sid:2100585; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap sadmind request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,20

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100589
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap yppasswd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A9|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,14; classtype:rpc-portmap-decode; sid:2100589; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap yppasswd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,14

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100590
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ypserv request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A4|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,12; reference:bugtraq,5914; reference:bugtraq,6016; reference:cve,2000-1042; reference:cve,2000-1043; reference:cve,2002-1232; classtype:rpc-portmap-decode; sid:2100590; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ypserv request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,12|bugtraq,5914|bugtraq,6016|cve,2000-1042|cve,2000-1043|cve,2002-1232

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100591
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ypupdated request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 BC|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,125; classtype:rpc-portmap-decode; sid:2100591; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ypupdated request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,125

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100593
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap snmpXdmi request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 99|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2417; reference:cve,2001-0236; reference:url,www.cert.org/advisories/CA-2001-05.html; classtype:rpc-portmap-decode; sid:2100593; rev:19; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap snmpXdmi request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2417|cve,2001-0236|url,www.cert.org/advisories/CA-2001-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 19

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100595
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap espd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 05 F7|u"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:bugtraq,2714; reference:cve,2001-0331; classtype:rpc-portmap-decode; sid:2100595; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap espd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2714|cve,2001-0331

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100598
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap listing TCP 111"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 04|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,428; classtype:rpc-portmap-decode; sid:2100598; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap listing TCP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,428

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100601
`alert tcp $EXTERNAL_NET any -> $HOME_NET 513 (msg:"GPL RPC rlogin LinuxNIS"; flow:to_server,established; content:"|3A 3A 3A 3A 3A 3A 3A 3A 00 3A 3A 3A 3A 3A 3A 3A 3A|"; classtype:bad-unknown; sid:2100601; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin LinuxNIS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100605
`alert tcp $HOME_NET 513 -> $EXTERNAL_NET any (msg:"GPL RPC rlogin login failure"; flow:from_server,established; content:"login incorrect"; reference:arachnids,393; classtype:unsuccessful-user; sid:2100605; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin login failure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : arachnids,393

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100611
`alert tcp $HOME_NET 513 -> $EXTERNAL_NET any (msg:"GPL RPC rlogin login failure"; flow:from_server,established; content:"|01|rlogind|3A| Permission denied."; reference:arachnids,392; classtype:unsuccessful-user; sid:2100611; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rlogin login failure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : arachnids,392

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100574
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL RPC mountd TCP export request"; flow:to_server,established; content:"|00 01 86 A5|"; depth:4; offset:16; content:"|00 00 00 05|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,26; classtype:attempted-recon; sid:2100574; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mountd TCP export request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,26

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100575
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap admind request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 F7|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,18; classtype:rpc-portmap-decode; sid:2100575; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap admind request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,18

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100576
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap amountd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 03|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,19; classtype:rpc-portmap-decode; sid:2100576; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap amountd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,19

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100577
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap bootparam request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 BA|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,16; reference:cve,1999-0647; classtype:rpc-portmap-decode; sid:2100577; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap bootparam request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,16|cve,1999-0647

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100578
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap cmsd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 E4|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,17; classtype:rpc-portmap-decode; sid:2100578; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap cmsd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,17

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101280
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap listing UDP 111"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 04|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,428; classtype:rpc-portmap-decode; sid:2101280; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap listing UDP 111** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,428

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100579
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap mountd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A5|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,13; classtype:rpc-portmap-decode; sid:2100579; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap mountd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,13

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100580
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap nisd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 CC|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,21; classtype:rpc-portmap-decode; sid:2100580; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap nisd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,21

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100581
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap pcnfsd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 02|I|F1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,22; classtype:rpc-portmap-decode; sid:2100581; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap pcnfsd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,22

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100582
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rexd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,23; classtype:rpc-portmap-decode; sid:2100582; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rexd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,23

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100583
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rstatd request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,10; classtype:rpc-portmap-decode; sid:2100583; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rstatd request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,10

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100584
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rusers request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A2|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,133; reference:cve,1999-0626; classtype:rpc-portmap-decode; sid:2100584; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rusers request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,133|cve,1999-0626

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100586
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap selection_svc request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 AF|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,25; classtype:rpc-portmap-decode; sid:2100586; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap selection_svc request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,25

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101279
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap snmpXdmi request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 99|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:bugtraq,2417; reference:cve,2001-0236; reference:url,www.cert.org/advisories/CA-2001-05.html; classtype:rpc-portmap-decode; sid:2101279; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap snmpXdmi request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : bugtraq,2417|cve,2001-0236|url,www.cert.org/advisories/CA-2001-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100587
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap status request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B8|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,15; classtype:rpc-portmap-decode; sid:2100587; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap status request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,15

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100588
`alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ttdbserv request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 F3|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,24; reference:bugtraq,122; reference:bugtraq,3382; reference:cve,1999-0003; reference:cve,1999-0687; reference:cve,1999-1075; reference:cve,2001-0717; reference:url,www.cert.org/advisories/CA-2001-05.html; classtype:rpc-portmap-decode; sid:2100588; rev:18; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ttdbserv request UDP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,24|bugtraq,122|bugtraq,3382|cve,1999-0003|cve,1999-0687|cve,1999-1075|cve,2001-0717|url,www.cert.org/advisories/CA-2001-05.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 18

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101271
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rusers request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A2|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,133; reference:cve,1999-0626; classtype:rpc-portmap-decode; sid:2101271; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rusers request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,133|cve,1999-0626

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101265
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap cmsd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 E4|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,17; classtype:rpc-portmap-decode; sid:2101265; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap cmsd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,17

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101269
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rexd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 B1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,23; classtype:rpc-portmap-decode; sid:2101269; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rexd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,23

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101275
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap yppasswd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A9|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,14; classtype:rpc-portmap-decode; sid:2101275; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap yppasswd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,14

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101262
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap admind request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 F7|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,18; classtype:rpc-portmap-decode; sid:2101262; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap admind request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,18

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101270
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rstatd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,10; classtype:rpc-portmap-decode; sid:2101270; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap rstatd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,10

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101273
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap selection_svc request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 AF|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,25; classtype:rpc-portmap-decode; sid:2101273; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap selection_svc request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,25

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101268
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap pcnfsd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 02|I|F1|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,22; classtype:rpc-portmap-decode; sid:2101268; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap pcnfsd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,22

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101263
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap amountd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 03|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,19; classtype:rpc-portmap-decode; sid:2101263; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap amountd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,19

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101267
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap nisd request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 CC|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,21; classtype:rpc-portmap-decode; sid:2101267; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap nisd request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,21

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101272
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap sadmind request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 87 88|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,20; classtype:rpc-portmap-decode; sid:2101272; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap sadmind request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,20

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101276
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap ypserv request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A4|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,12; reference:bugtraq,5914; reference:bugtraq,6016; reference:cve,2000-1042; reference:cve,2000-1043; reference:cve,2002-1232; classtype:rpc-portmap-decode; sid:2101276; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap ypserv request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,12|bugtraq,5914|bugtraq,6016|cve,2000-1042|cve,2000-1043|cve,2002-1232

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101264
`alert tcp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap bootparam request TCP"; flow:to_server,established; content:"|00 01 86 A0|"; depth:4; offset:16; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 BA|"; within:4; content:"|00 00 00 00|"; depth:4; offset:8; reference:arachnids,16; reference:cve,1999-0647; classtype:rpc-portmap-decode; sid:2101264; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **portmap bootparam request TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : rpc-portmap-decode

URL reference : arachnids,16|cve,1999-0647

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : RPC

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

