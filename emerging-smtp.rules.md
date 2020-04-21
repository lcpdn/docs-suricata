# 2012054
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"ET SMTP Potential Exim HeaderX with run exploit attempt"; flow:established,to_server; content:"|0d 0a|HeaderX|3a 20|"; nocase; content:"run{"; distance:0; reference:url,www.exim.org/lurker/message/20101207.215955.bb32d4f2.en.html; reference:url,eclists.org/fulldisclosure/2010/Dec/221; classtype:attempted-admin; sid:2012054; rev:3; metadata:created_at 2010_12_14, updated_at 2010_12_14;)
` 

Name : **Potential Exim HeaderX with run exploit attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.exim.org/lurker/message/20101207.215955.bb32d4f2.en.html|url,eclists.org/fulldisclosure/2010/Dec/221

CVE reference : Not defined

Creation date : 2010-12-14

Last modified date : 2010-12-14

Rev version : 3

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012135
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET SMTP IBM Lotus Domino iCalendar Email Address Stack Buffer Overflow Attempt"; flow:to_server,established; content:"|0d 0a|ORGANIZER"; content:"mailto|3a|"; nocase; within:50; isdataat:2000,relative; content:!"|0a|"; within:2000; reference:url,www.exploit-db.com/exploits/15005/; reference:cve,2010-3407; classtype:attempted-user; sid:2012135; rev:3; metadata:created_at 2011_01_05, updated_at 2011_01_05;)
` 

Name : **IBM Lotus Domino iCalendar Email Address Stack Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.exploit-db.com/exploits/15005/|cve,2010-3407

CVE reference : Not defined

Creation date : 2011-01-05

Last modified date : 2011-01-05

Rev version : 3

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012986
`alert tcp $EXTERNAL_NET 25 -> $HOME_NET any (msg:"ET SMTP Robtex.com Block Message"; flow:established,from_server; content:"robtex.com"; classtype:not-suspicious; sid:2012986; rev:2; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **Robtex.com Block Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 2

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102275
`alert tcp $SMTP_SERVERS 25 -> $EXTERNAL_NET any (msg:"GPL SMTP AUTH LOGON brute force attempt"; flow:from_server,established; content:"Authentication unsuccessful"; offset:54; nocase; threshold:type threshold, track by_dst, count 5, seconds 60; classtype:suspicious-login; sid:2102275; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AUTH LOGON brute force attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102590
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP MAIL FROM overflow attempt"; flow:to_server,established; content:"MAIL FROM"; nocase; isdataat:260; content:!"|0A|"; within:256; reference:bugtraq,10290; reference:bugtraq,7506; reference:cve,2004-0399; reference:url,www.guninski.com/exim1.html; classtype:attempted-admin; sid:2102590; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MAIL FROM overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10290|bugtraq,7506|cve,2004-0399|url,www.guninski.com/exim1.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100567
`#alert tcp $SMTP_SERVERS 25 -> $EXTERNAL_NET any (msg:"GPL SMTP SMTP relaying denied"; flow:established,from_server; content:"550 5.7.1"; depth:70; reference:arachnids,249; reference:url,mail-abuse.org/tsi/ar-fix.html; classtype:misc-activity; sid:2100567; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SMTP relaying denied** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,249|url,mail-abuse.org/tsi/ar-fix.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100721
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"GPL SMTP OUTBOUND bad file attachment"; flow:to_server,established; content:"Content-Disposition|3A|"; nocase; content:"filename"; distance:0; pcre:"/filename\s*=\s*.*?\.(?=[abcdehijlmnoprsvwx])(a(d[ep]|s[dfx])|c([ho]m|li|md|pp)|d(iz|ll|ot)|e(m[fl]|xe)|h(lp|sq|ta)|jse?|m(d[abew]|s[ip])|p(p[st]|if|[lm]|ot)|r(eg|tf)|s(cr|[hy]s|wf)|v(b[es]?|cf|xd)|w(m[dfsz]|p[dmsz]|s[cfh])|xl[tw]|bat|ini|lnk|nws|ocx)[\x27\x22\n\r\s]/iR"; classtype:suspicious-filename-detect; sid:2100721; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **OUTBOUND bad file attachment** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100631
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP ehlo cybercop attempt"; flow:to_server,established; content:"ehlo cybercop|0A|quit|0A|"; reference:arachnids,372; classtype:protocol-command-decode; sid:2100631; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ehlo cybercop attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : arachnids,372

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101450
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP expn *@"; flow:to_server,established; content:"expn"; nocase; content:"*@"; pcre:"/^expn\s+\*@/smi"; reference:cve,1999-1200; classtype:misc-attack; sid:2101450; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **expn *@** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : cve,1999-1200

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100632
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP expn cybercop attempt"; flow:to_server,established; content:"expn cybercop"; reference:arachnids,371; classtype:protocol-command-decode; sid:2100632; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **expn cybercop attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : arachnids,371

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100659
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP expn decode"; flow:to_server,established; content:"expn"; nocase; content:"decode"; nocase; pcre:"/^expn\s+decode/smi"; reference:arachnids,32; reference:cve,1999-0096; reference:nessus,10248; classtype:attempted-recon; sid:2100659; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **expn decode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,32|cve,1999-0096|nessus,10248

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100660
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP expn root"; flow:to_server,established; content:"expn"; nocase; content:"root"; fast_pattern; distance:0; nocase; pcre:"/^expn\s+root/smi"; reference:arachnids,31; reference:cve,1999-0531; reference:nessus,10249; classtype:attempted-recon; sid:2100660; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **expn root** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,31|cve,1999-0531|nessus,10249

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100672
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP vrfy decode"; flow:to_server,established; content:"vrfy"; nocase; content:"decode"; distance:1; nocase; pcre:"/^vrfy\s+decode/smi"; reference:arachnids,373; reference:bugtraq,10248; reference:cve,1999-0096; classtype:attempted-recon; sid:2100672; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **vrfy decode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,373|bugtraq,10248|cve,1999-0096

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101446
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP vrfy root"; flow:to_server,established; content:"vrfy"; nocase; content:"root"; distance:1; nocase; pcre:"/^vrfy\s+root/smi"; classtype:attempted-recon; sid:2101446; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **vrfy root** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100654
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP RCPT TO overflow"; flow:to_server,established; content:"rcpt to|3A|"; nocase; content:!"|0a|"; within:300; isdataat:300; pcre:"/^RCPT TO\x3a\s[^\n]{300}/ism"; reference:bugtraq,2283; reference:bugtraq,9696; reference:cve,2001-0260; classtype:attempted-admin; sid:2100654; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RCPT TO overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2283|bugtraq,9696|cve,2001-0260

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102259
`alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP EXPN overflow attempt"; flow:to_server,established; content:"EXPN"; nocase; isdataat:255,relative; content:!"|0a|"; within:255; pcre:"/^EXPN[^\n]{255}/smi"; reference:bugtraq,6991; reference:bugtraq,7230; reference:cve,2002-1337; reference:cve,2003-0161; classtype:attempted-admin; sid:2102259; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **EXPN overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,6991|bugtraq,7230|cve,2002-1337|cve,2003-0161

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SMTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018144
`alert smtp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SMTP EXE - ZIP file with .pif filename inside"; flow:established; content:"|0D 0A 0D 0A|UmFyI"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?(LnBpZ|5waW|ucGlm)/R"; classtype:bad-unknown; sid:2018144; rev:2; metadata:created_at 2014_02_14, updated_at 2014_02_14;)
` 

Name : **EXE - ZIP file with .pif filename inside** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-02-14

Last modified date : 2014-02-14

Rev version : 2

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019407
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M2"; flow:established,to_server; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?c[\x0d\x0a]{0,2}H[\x0d\x0a]{0,2}B[\x0d\x0a]{0,2}0[\x0d\x0a]{0,2}L[\x0d\x0a]{0,2}2[\x0d\x0a]{0,2}V[\x0d\x0a]{0,2}t[\x0d\x0a]{0,2}Y[\x0d\x0a]{0,2}m[\x0d\x0a]{0,2}V[\x0d\x0a]{0,2}k[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}G[\x0d\x0a]{0,2}l[\x0d\x0a]{0,2}u[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}3[\x0d\x0a]{0,2}M[\x0d\x0a]{0,2}v[\x0d\x0a]{0,2}b[\x0d\x0a]{0,2}2[\x0d\x0a]{0,2}x[\x0d\x0a]{0,2}l[\x0d\x0a]{0,2}T[\x0d\x0a]{0,2}2[\x0d\x0a]{0,2}J[\x0d\x0a]{0,2}q[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}W[\x0d\x0a]{0,2}N[\x0d\x0a]{0,2}0/R"; metadata: former_category SMTP; classtype:misc-activity; sid:2019407; rev:2; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019408
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M3"; flow:established,to_server; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?c[\x0d\x0a]{0,2}H[\x0d\x0a]{0,2}Q[\x0d\x0a]{0,2}v[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}W[\x0d\x0a]{0,2}1[\x0d\x0a]{0,2}i[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}W[\x0d\x0a]{0,2}R[\x0d\x0a]{0,2}k[\x0d\x0a]{0,2}a[\x0d\x0a]{0,2}W[\x0d\x0a]{0,2}5[\x0d\x0a]{0,2}n[\x0d\x0a]{0,2}c[\x0d\x0a]{0,2}y[\x0d\x0a]{0,2}9[\x0d\x0a]{0,2}v[\x0d\x0a]{0,2}b[\x0d\x0a]{0,2}G[\x0d\x0a]{0,2}V[\x0d\x0a]{0,2}P[\x0d\x0a]{0,2}Y[\x0d\x0a]{0,2}m[\x0d\x0a]{0,2}p[\x0d\x0a]{0,2}l[\x0d\x0a]{0,2}Y[\x0d\x0a]{0,2}3/R"; metadata: former_category SMTP; classtype:misc-activity; sid:2019408; rev:2; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019409
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M4"; flow:established,to_server; content:"cHB0L2VtYmVkZGluZ3Mvb2xlT2JqZWN0"; metadata: former_category SMTP; classtype:misc-activity; sid:2019409; rev:2; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019410
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M5"; flow:established,to_server; content:"cHQvZW1iZWRkaW5ncy9vbGVPYmplY3"; metadata: former_category SMTP; classtype:misc-activity; sid:2019410; rev:2; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019411
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M6"; flow:established,to_server; content:"BwdC9lbWJlZGRpbmdzL29sZU9iamVjd"; metadata: former_category SMTP; classtype:misc-activity; sid:2019411; rev:2; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019406
`alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"ET SMTP SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M1"; flow:established,to_server; content:"|0D 0A 0D 0A|UEsDB"; pcre:"/^[A-Za-z0-9\/\+\x0D\x0A]+?B[\x0d\x0a]{0,2}w[\x0d\x0a]{0,2}d[\x0d\x0a]{0,2}C[\x0d\x0a]{0,2}9[\x0d\x0a]{0,2}l[\x0d\x0a]{0,2}b[\x0d\x0a]{0,2}W[\x0d\x0a]{0,2}J[\x0d\x0a]{0,2}l[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}G[\x0d\x0a]{0,2}R[\x0d\x0a]{0,2}p[\x0d\x0a]{0,2}b[\x0d\x0a]{0,2}m[\x0d\x0a]{0,2}d[\x0d\x0a]{0,2}z[\x0d\x0a]{0,2}L[\x0d\x0a]{0,2}2[\x0d\x0a]{0,2}9[\x0d\x0a]{0,2}s[\x0d\x0a]{0,2}Z[\x0d\x0a]{0,2}U[\x0d\x0a]{0,2}9[\x0d\x0a]{0,2}i[\x0d\x0a]{0,2}a[\x0d\x0a]{0,2}m[\x0d\x0a]{0,2}V[\x0d\x0a]{0,2}j[\x0d\x0a]{0,2}d/R"; metadata: former_category SMTP; classtype:misc-activity; sid:2019406; rev:3; metadata:created_at 2014_10_15, updated_at 2014_10_15;)
` 

Name : **SUSPICIOUS SMTP Attachment Inbound PPT attachment with Embedded OLE Object M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-10-15

Last modified date : 2014-10-15

Rev version : 3

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012985
`alert tcp $EXTERNAL_NET 25 -> $HOME_NET any (msg:"ET SMTP Sorbs.net Block Message"; flow:established,from_server; content:"sorbs.net"; classtype:not-suspicious; sid:2012985; rev:2; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **Sorbs.net Block Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 2

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012984
`#alert tcp $EXTERNAL_NET 25 -> $HOME_NET any (msg:"ET SMTP Sophos.com Block Message"; flow:established,from_server; content:"sophos.com"; classtype:not-suspicious; sid:2012984; rev:2; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **Sophos.com Block Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 2

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023255
`alert tcp any any -> $SMTP_SERVERS [25,587] (msg:"ET SMTP Incoming SMTP Message with Possibly Malicious MIME Epilogue 2016-05-13 (BadEpilogue)"; flow:to_server,established; content:"|0d 0a|Content-Type|3a 20|multipart|2f|mixed|3b|"; fast_pattern:12,20; content:"|0d 0a 2d 2d|"; distance:0; pcre:"/^(?P<boundary>[\x20\x27-\x29\x2b-\x2f0-9\x3a\x3d\x3fA-Z\x5fa-z]{0,69}?[^\x2d])--(?:\x0d\x0a(?!--|\x2e|RSET)[^\r\n]*?)*\x0d\x0a--(?P=boundary)\x0d\x0a/R"; reference:url,www.certego.local/en/news/badepilogue-the-perfect-evasion/; classtype:bad-unknown; sid:2023255; rev:1; metadata:attack_target SMTP_Server, deployment Datacenter, signature_severity Major, created_at 2016_09_22, performance_impact Low, updated_at 2016_09_22;)
` 

Name : **Incoming SMTP Message with Possibly Malicious MIME Epilogue 2016-05-13 (BadEpilogue)** 

Attack target : SMTP_Server

Description : Alerts on a possible improper MIME message that may bypass AV and anti-spam scanning technologies, but may be handled correctly by e-mail clients.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.certego.local/en/news/badepilogue-the-perfect-evasion/

CVE reference : Not defined

Creation date : 2016-09-22

Last modified date : 2016-09-22

Rev version : 1

Category : SMTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2012982
`alert smtp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SMTP Abuseat.org Block Message"; flow:established,from_server; content:"abuseat.org"; classtype:not-suspicious; sid:2012982; rev:4; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **Abuseat.org Block Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 4

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012983
`alert smtp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SMTP Spamcop.net Block Message"; flow:established,from_server; content:"spamcop.net"; classtype:not-suspicious; sid:2012983; rev:3; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **Spamcop.net Block Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 3

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019340
`alert smtp any any -> any any (msg:"ET SMTP Possible ComputerCop Log Transmitted via SMTP"; flow:to_server,established; content:"Subject|3a 20|CCOP|20|"; nocase; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,www.eff.org/deeplinks/2014/09/computercop-dangerous-internet-safety-software-hundreds-police-agencies; classtype:trojan-activity; sid:2019340; rev:3; metadata:created_at 2014_10_02, updated_at 2019_10_07;)
` 

Name : **Possible ComputerCop Log Transmitted via SMTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.eff.org/deeplinks/2014/09/computercop-dangerous-internet-safety-software-hundreds-police-agencies

CVE reference : Not defined

Creation date : 2014-10-02

Last modified date : 2019-10-07

Rev version : 3

Category : SMTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

