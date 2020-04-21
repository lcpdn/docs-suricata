# 2002925
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET INAPPROPRIATE Google Image Search, Safe Mode Off"; flow:established,to_server; uricontent:"&safe=off"; content:"|0d 0a|Host|3a| images.google.com|0d 0a|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002925; classtype:policy-violation; sid:2002925; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Google Image Search, Safe Mode Off** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002925

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001346
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn preteen"; flow: from_server,established; content:"preteen"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001346; classtype:policy-violation; sid:2001346; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn preteen** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001346

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001347
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn pre-teen"; flow: from_server,established; content:"pre-teen"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001347; classtype:policy-violation; sid:2001347; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn pre-teen** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001347

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001348
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn early teen"; flow: from_server,established; content:"early teen"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001348; classtype:policy-violation; sid:2001348; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn early teen** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001348

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001387
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn zeps"; flow: from_server,established; content:" zeps "; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001387; classtype:policy-violation; sid:2001387; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn zeps** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001387

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001388
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn r@ygold"; flow: from_server,established; content:" r@ygold "; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001388; classtype:policy-violation; sid:2001388; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn r@ygold** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001388

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001389
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn childlover"; flow: from_server,established; content:" childlover "; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001389; classtype:policy-violation; sid:2001389; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn childlover** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001389

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001349
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE free XXX"; flow: to_client,established; content:"FREE XXX"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001349; classtype:policy-violation; sid:2001349; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **free XXX** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001349

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001350
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE hardcore anal"; flow: to_client,established; content:"hardcore anal"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001350; classtype:policy-violation; sid:2001350; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **hardcore anal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001350

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001351
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE masturbation"; flow: to_client,established; content:"masturbat"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001351; classtype:policy-violation; sid:2001351; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **masturbation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001351

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001352
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE ejaculation"; flow: to_client,established; content:"ejaculat"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001352; classtype:policy-violation; sid:2001352; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ejaculation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001352

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001353
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE BDSM"; flow: to_client,established; content:"BDSM"; nocase; threshold: type threshold, track by_dst,count 5, seconds 360; reference:url,doc.emergingthreats.net/bin/view/Main/2001353; classtype:policy-violation; sid:2001353; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **BDSM** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001353

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001392
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Sextracker Tracking Code Detected (1)"; flow: from_server,established; content:"BEGIN SEXLIST REFERRER-STATS CODE"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001392; classtype:policy-violation; sid:2001392; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sextracker Tracking Code Detected (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001392

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001393
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Sextracker Tracking Code Detected (2)"; flow: from_server,established; content:"BEGIN SEXTRACKER CODE"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001393; classtype:policy-violation; sid:2001393; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Sextracker Tracking Code Detected (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001393

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001608
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Likely Porn"; flow: established,from_server; pcre:"/ (FREE XXX|dildo|masturbat|oral sex|ejaculat|up skirt|tits|bondage|lolita|clitoris|cock suck|hardcore (teen|anal|sex|porn)|raw sex|((fuck|sex|porn|xxx) (movies|dvd))|((naked|nude) (celeb|lesbian)))\b/i"; reference:url,doc.emergingthreats.net/bin/view/Main/2001608; classtype:policy-violation; sid:2001608; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Likely Porn** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001608

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001386
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET INAPPROPRIATE Kiddy Porn pthc"; flow: from_server,established; content:" pthc "; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001386; classtype:policy-violation; sid:2001386; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Kiddy Porn pthc** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001386

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101837
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE alt.binaries.pictures.tinygirls"; flow:to_client,established; content:"alt.binaries.pictures.tinygirls"; nocase; classtype:policy-violation; sid:2101837; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **alt.binaries.pictures.tinygirls** 

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

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101317
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE anal sex"; flow:to_client,established; content:"anal sex"; nocase; classtype:policy-violation; sid:2101317; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **anal sex** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101316
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE fuck fuck fuck"; flow:to_client,established; content:"fuck fuck fuck"; nocase; classtype:policy-violation; sid:2101316; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **fuck fuck fuck** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101320
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE fuck movies"; flow:to_client,established; content:"fuck movies"; nocase; classtype:policy-violation; sid:2101320; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **fuck movies** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101311
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE hardcore anal"; flow:to_client,established; content:"hardcore anal"; nocase; classtype:policy-violation; sid:2101311; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **hardcore anal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101318
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE hardcore rape"; flow:to_client,established; content:"hardcore rape"; nocase; classtype:policy-violation; sid:2101318; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **hardcore rape** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101315
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE hot young sex"; flow:to_client,established; content:"hot young sex"; nocase; classtype:policy-violation; sid:2101315; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **hot young sex** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101833
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE naked lesbians"; flow:to_client,established; content:"naked lesbians"; nocase; classtype:policy-violation; sid:2101833; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **naked lesbians** 

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

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101313
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL INAPPROPRIATE up skirt"; flow:to_client,established; content:"up skirt"; nocase; classtype:policy-violation; sid:2101313; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **up skirt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : INAPPROPRIATE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

