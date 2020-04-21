# 2101993
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP login literal buffer overflow attempt"; flow:established,to_server; content:"LOGIN"; nocase; pcre:"/\sLOGIN\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,6298; classtype:misc-attack; sid:2101993; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **login literal buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,6298

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101902
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP lsub literal overflow attempt"; flow:to_server,established; content:"LSUB"; nocase; pcre:"/\sLSUB\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101902; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **lsub literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101903
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP rename overflow attempt"; flow:established,to_server; content:"RENAME"; nocase; isdataat:100,relative; pcre:"/\sRENAME\s[^\n]{100}/smi"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101903; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rename overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101904
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP find overflow attempt"; flow:established,to_server; content:"FIND"; nocase; isdataat:100,relative; pcre:"/\sFIND\s[^\n]{100}/smi"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101904; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **find overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103070
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP fetch overflow attempt"; flow:established,to_server; content:"FETCH"; nocase; isdataat:500,relative; pcre:"/\sFETCH\s[^\n]{500}/smi"; reference:bugtraq,11775; classtype:misc-attack; sid:2103070; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **fetch overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101842
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP login buffer overflow attempt"; flow:established,to_server; content:"LOGIN"; isdataat:100,relative; pcre:"/\sLOGIN\s[^\n]{100}/smi"; reference:bugtraq,13727; reference:bugtraq,502; reference:cve,1999-0005; reference:cve,1999-1557; reference:cve,2005-1255; reference:nessus,10123; reference:cve,2007-2795; reference:nessus,10125; classtype:attempted-user; sid:2101842; rev:16; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **login buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,13727|bugtraq,502|cve,1999-0005|cve,1999-1557|cve,2005-1255|nessus,10123|cve,2007-2795|nessus,10125

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 16

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101844
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP authenticate overflow attempt"; flow:established,to_server; content:"AUTHENTICATE"; nocase; isdataat:100,relative; pcre:"/\sAUTHENTICATE\s[^\n]{100}/smi"; reference:bugtraq,12995; reference:bugtraq,130; reference:cve,1999-0005; reference:cve,1999-0042; reference:nessus,10292; classtype:misc-attack; sid:2101844; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **authenticate overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,12995|bugtraq,130|cve,1999-0005|cve,1999-0042|nessus,10292

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101845
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP list literal overflow attempt"; flow:established,to_server; content:"LIST"; nocase; pcre:"/\sLIST\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101845; rev:16; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **list literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 16

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101780
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP EXPLOIT partial body overflow attempt"; dsize:>1092; flow:to_server,established; content:" x PARTIAL 1 BODY["; reference:bugtraq,4713; reference:cve,2002-0379; classtype:misc-attack; sid:2101780; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **EXPLOIT partial body overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,4713|cve,2002-0379

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101755
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP partial body buffer overflow attempt"; flow:to_server,established; content:"PARTIAL"; nocase; content:"BODY["; distance:0; nocase; pcre:"/\sPARTIAL.*BODY\[[^\]]{1024}/smi"; reference:bugtraq,4713; reference:cve,2002-0379; classtype:misc-attack; sid:2101755; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **partial body buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,4713|cve,2002-0379

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102330
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP auth overflow attempt"; flow:established,to_server; content:"AUTH"; nocase; isdataat:100,relative; pcre:"/AUTH\s[^\n]{100}/smi"; reference:bugtraq,8861; classtype:misc-attack; sid:2102330; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **auth overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,8861

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102120
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP create literal buffer overflow attempt"; flow:to_server,established; content:"CREATE"; nocase; content:"{"; distance:1; pcre:"/\sCREATE\s*\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,7446; classtype:misc-attack; sid:2102120; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **create literal buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,7446

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102119
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP rename literal overflow attempt"; flow:established,to_server; content:"RENAME"; nocase; content:"{"; distance:1; pcre:"/\sRENAME\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2102119; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rename literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102118
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP list overflow attempt"; flow:established,to_server; content:"LIST"; nocase; isdataat:100,relative; pcre:"/\sLIST\s[^\n]{100}/smi"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2102118; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **list overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102107
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP create buffer overflow attempt"; flow:to_server,established; content:"CREATE"; isdataat:1024,relative; pcre:"/\sCREATE\s[^\n]{1024}/smi"; reference:bugtraq,7446; classtype:misc-attack; sid:2102107; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **create buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,7446

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102106
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP lsub overflow attempt"; flow:to_server,established; content:"LSUB"; isdataat:100,relative; pcre:"/\sLSUB\s[^\n]{100}/smi"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2102106; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **lsub overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110|cve,2000-0284|nessus,10374

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102105
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP authenticate literal overflow attempt"; flow:established,to_server; content:"AUTHENTICATE"; nocase; pcre:"/\sAUTHENTICATE\s[^\n]*?\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:cve,1999-0042; reference:nessus,10292; classtype:misc-attack; sid:2102105; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **authenticate literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : cve,1999-0042|nessus,10292

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102046
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP partial body.peek buffer overflow attempt"; flow:to_server,established; content:"PARTIAL"; nocase; content:"BODY.PEEK["; isdataat:1024,relative; distance:0; nocase; pcre:"/\sPARTIAL.*BODY\.PEEK\[[^\]]{1024}/smi"; reference:bugtraq,4713; reference:cve,2002-0379; classtype:misc-attack; sid:2102046; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **partial body.peek buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,4713|cve,2002-0379

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103076
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP unsubscribe overflow attempt"; flow:established,to_server; content:"UNSUBSCRIBE"; nocase; isdataat:100,relative; pcre:"/\sUNSUBSCRIBE\s[^\n]{100}/smi"; reference:bugtraq,11775; classtype:misc-attack; sid:2103076; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unsubscribe overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103075
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP unsubscribe literal overflow attempt"; flow:established,to_server; content:"UNSUBSCRIBE"; nocase; pcre:"/\sUNSUBSCRIBE\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,11775; classtype:misc-attack; sid:2103075; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unsubscribe literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103074
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP subscribe overflow attempt"; flow:established,to_server; content:"SUBSCRIBE"; nocase; isdataat:100,relative; pcre:"/\sSUBSCRIBE\s[^\n]{100}/smi"; reference:bugtraq,11775; classtype:misc-attack; sid:2103074; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **subscribe overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103073
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP subscribe literal overflow attempt"; flow:established,to_server; content:"SUBSCRIBE"; nocase; pcre:"/\sSUBSCRIBE\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,11775; classtype:misc-attack; sid:2103073; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **subscribe literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103072
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP status overflow attempt"; flow:established,to_server; content:"STATUS"; nocase; isdataat:100,relative; pcre:"/\sSTATUS\s[^\n]{100}/smi"; reference:bugtraq,11775; reference:bugtraq,13727; reference:cve,2005-1256; classtype:misc-attack; sid:2103072; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **status overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775|bugtraq,13727|cve,2005-1256

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103071
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP status literal overflow attempt"; flow:established,to_server; content:"STATUS"; nocase; pcre:"/\sSTATUS\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,11775; classtype:misc-attack; sid:2103071; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **status literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103069
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP fetch literal overflow attempt"; flow:established,to_server; content:"FETCH"; nocase; pcre:"/\sFETCH\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,11775; classtype:misc-attack; sid:2103069; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **fetch literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103068
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP examine overflow attempt"; flow:established,to_server; content:"EXAMINE"; nocase; isdataat:100,relative; pcre:"/\sEXAMINE\s[^\n]{100}/smi"; reference:bugtraq,11775; classtype:misc-attack; sid:2103068; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **examine overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103067
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP examine literal overflow attempt"; flow:established,to_server; content:"EXAMINE"; nocase; pcre:"/\sEXAMINE\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,11775; classtype:misc-attack; sid:2103067; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **examine literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103066
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP append overflow attempt"; flow:established,to_server; content:"APPEND"; nocase; isdataat:100,relative; pcre:"/\sAPPEND\s[^\n]{256}/smi"; reference:bugtraq,11775; classtype:misc-attack; sid:2103066; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **append overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11775

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103058
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP copy literal overflow attempt"; flow:established,to_server; content:"COPY"; nocase; pcre:"/\sCOPY\s[^\n]*?\{/smi"; byte_test:5,>,1024,0,string,dec,relative; reference:bugtraq,1110; classtype:misc-attack; sid:2103058; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **copy literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,1110

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103008
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP delete literal overflow attempt"; flow:established,to_server; content:"DELETE"; nocase; pcre:"/\sDELETE\s[^\n]*?\{/smi"; byte_test:5,>,100,0,string,dec,relative; reference:bugtraq,11675; classtype:misc-attack; sid:2103008; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **delete literal overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11675

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103007
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP delete overflow attempt"; flow:established,to_server; content:"DELETE"; nocase; isdataat:100,relative; pcre:"/\sDELETE\s[^\n]{100}/smi"; reference:bugtraq,11675; classtype:misc-attack; sid:2103007; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **delete overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,11675

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102665
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP login literal format string attempt"; flow:established,to_server; content:"LOGIN"; nocase; pcre:"/\sLOGIN\s\w+\s\{\d+\}[\r]?\n[^\n]*?%/smi"; reference:bugtraq,10976; classtype:attempted-admin; sid:2102665; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **login literal format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10976

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100293
`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP Overflow Attempt"; flow:to_server,established; content:"|E8 C0 FF FF FF|/bin/sh"; classtype:attempted-admin; sid:2100293; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Overflow Attempt** 

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

Category : IMAP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

