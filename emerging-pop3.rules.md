# 2101936
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 AUTH overflow attempt"; flow:to_server,established; content:"AUTH"; nocase; isdataat:50,relative; pcre:"/^AUTH\s[^\n]{50}/smi"; reference:bugtraq,830; reference:cve,1999-0822; reference:nessus,10184; classtype:attempted-admin; sid:2101936; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AUTH overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,830|cve,1999-0822|nessus,10184

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101937
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 LIST overflow attempt"; flow:to_server,established; content:"LIST"; nocase; isdataat:10,relative; pcre:"/^LIST\s[^\n]{10}/smi"; reference:bugtraq,948; reference:cve,2000-0096; reference:nessus,10197; classtype:attempted-admin; sid:2101937; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **LIST overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,948|cve,2000-0096|nessus,10197

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101938
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 XTND overflow attempt"; flow:to_server,established; content:"XTND"; nocase; isdataat:50,relative; pcre:"/^XTND\s[^\n]{50}/smi"; classtype:attempted-admin; sid:2101938; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **XTND overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101635
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 APOP overflow attempt"; flow:to_server,established; content:"APOP"; nocase; isdataat:256,relative; pcre:"/^APOP\s[^\n]{256}/smi"; reference:bugtraq,1652; reference:cve,2000-0840; reference:cve,2000-0841; reference:nessus,10559; classtype:attempted-admin; sid:2101635; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **APOP overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,1652|cve,2000-0840|cve,2000-0841|nessus,10559

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101634
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 POP3 PASS overflow attempt"; flow:to_server,established; content:"PASS"; nocase; isdataat:50,relative; pcre:"/^PASS\s[^\n]{50}/smi"; reference:bugtraq,791; reference:cve,1999-1511; reference:nessus,10325; classtype:attempted-admin; sid:2101634; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **POP3 PASS overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,791|cve,1999-1511|nessus,10325

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102250
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 USER format string attempt"; flow:to_server,established; content:"USER"; nocase; pcre:"/^USER\s+[^\n]*?%/smi"; reference:bugtraq,10976; reference:bugtraq,7667; reference:cve,2003-0391; reference:nessus,11742; classtype:attempted-admin; sid:2102250; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **USER format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10976|bugtraq,7667|cve,2003-0391|nessus,11742

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102122
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 UIDL negative argument attempt"; flow:to_server,established; content:"UIDL"; nocase; pcre:"/^UIDL\s+-\d/smi"; reference:bugtraq,6053; reference:cve,2002-1539; reference:nessus,11570; classtype:misc-attack; sid:2102122; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **UIDL negative argument attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6053|cve,2002-1539|nessus,11570

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102121
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 DELE negative argument attempt"; flow:to_server,established; content:"DELE"; nocase; pcre:"/^DELE\s+-\d/smi"; reference:bugtraq,6053; reference:bugtraq,7445; reference:cve,2002-1539; classtype:misc-attack; sid:2102121; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DELE negative argument attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6053|bugtraq,7445|cve,2002-1539

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102112
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 RSET overflow attempt"; flow:to_server,established; content:"RSET"; nocase; isdataat:10,relative; pcre:"/^RSET\s[^\n]{10}/smi"; classtype:attempted-admin; sid:2102112; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RSET overflow attempt** 

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

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102111
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 DELE overflow attempt"; flow:to_server,established; content:"DELE"; nocase; isdataat:10,relative; pcre:"/^DELE\s[^\n]{10}/smi"; classtype:attempted-admin; sid:2102111; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DELE overflow attempt** 

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

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102110
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 STAT overflow attempt"; flow:to_server,established; content:"STAT"; nocase; isdataat:10,relative; pcre:"/^STAT\s[^\n]{10}/smi"; classtype:attempted-admin; sid:2102110; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STAT overflow attempt** 

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

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102109
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 TOP overflow attempt"; flow:to_server,established; content:"TOP"; nocase; isdataat:10,relative; pcre:"/^TOP\s[^\n]{10}/smi"; classtype:attempted-admin; sid:2102109; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TOP overflow attempt** 

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

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102108
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 CAPA overflow attempt"; flow:to_server,established; content:"CAPA"; nocase; isdataat:10,relative; pcre:"/^CAPA\s[^\n]{10}/smi"; classtype:attempted-admin; sid:2102108; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CAPA overflow attempt** 

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

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100286
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 x86 BSD overflow"; flow:to_server,established; content:"^|0E|1|C0 B0 3B 8D|~|0E 89 FA 89 F9|"; reference:bugtraq,133; reference:cve,1999-0006; reference:nessus,10196; classtype:attempted-admin; sid:2100286; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 BSD overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,133|cve,1999-0006|nessus,10196

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100287
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 x86 BSD overflow 2"; flow:to_server,established; content:"h]^|FF D5 FF D4 FF F5 8B F5 90|f1"; classtype:attempted-admin; sid:2100287; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 BSD overflow 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100288
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 x86 Linux overflow"; flow:to_server,established; content:"|D8|@|CD 80 E8 D9 FF FF FF|/bin/sh"; classtype:attempted-admin; sid:2100288; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 Linux overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100289
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 x86 SCO overflow"; flow:to_server,established; content:"V|0E|1|C0 B0 3B 8D|~|12 89 F9 89 F9|"; reference:bugtraq,156; reference:cve,1999-0006; classtype:attempted-admin; sid:2100289; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 SCO overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,156|cve,1999-0006

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102409
`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 APOP USER overflow attempt"; flow:to_server,established; content:"APOP"; nocase; isdataat:256,relative; pcre:"/^APOP\s+USER\s[^\n]{256}/smi"; reference:bugtraq,9794; classtype:attempted-admin; sid:2102409; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **APOP USER overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9794

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102666
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 PASS format string attempt"; flow:to_server,established; content:"PASS"; nocase; pcre:"/^PASS\s+[^\n]*?%/smi"; reference:bugtraq,10976; classtype:attempted-admin; sid:2102666; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PASS format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10976

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101866
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 USER overflow attempt"; flow:to_server,established; content:"USER"; nocase; isdataat:50,relative; pcre:"/^USER\s[^\n]{50}/smi"; reference:bugtraq,11256; reference:bugtraq,789; reference:cve,1999-0494; reference:nessus,10311; classtype:attempted-admin; sid:2101866; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **USER overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11256|bugtraq,789|cve,1999-0494|nessus,10311

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : POP3

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

