# 2003925
`#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET USER_AGENTS WebHack Control Center User-Agent Outbound (WHCC/)"; flow:to_server,established; content:"User-Agent|3a|"; nocase; content:"WHCC"; http_header; fast_pattern; nocase; pcre:"/^User-Agent\:[^\n]+WHCC/Hmi"; reference:url,www.governmentsecurity.org/forum/index.php?showtopic=5112&pid=28561&mode=threaded&start=; reference:url,doc.emergingthreats.net/2003925; classtype:trojan-activity; sid:2003925; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **WebHack Control Center User-Agent Outbound (WHCC/)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.governmentsecurity.org/forum/index.php?showtopic=5112&pid=28561&mode=threaded&start=|url,doc.emergingthreats.net/2003925

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003394
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET USER_AGENTS User Agent Containing http Suspicious - Likely Spyware/Trojan"; flow:to_server,established; content:"User-Agent|3a|"; nocase; content:!"rss"; nocase; pcre:"/User-Agent\:[^\n]+http\:\/\//i"; reference:url,doc.emergingthreats.net/bin/view/Main/2003394; classtype:trojan-activity; sid:2003394; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **User Agent Containing http Suspicious - Likely Spyware/Trojan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003394

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012180
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET USER_AGENTS Suspicious User Agent no space"; flow:established,to_server; content:"|0d 0a|User-Agent|3a|"; content:!"|0d 0a|User-Agent|3a 20|"; metadata: former_category HUNTING; classtype:bad-unknown; sid:2012180; rev:3; metadata:created_at 2011_01_14, updated_at 2011_01_14;)
` 

Name : **Suspicious User Agent no space** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-01-14

Last modified date : 2011-01-14

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003584
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Updater)"; flow:to_server,established; content:"User-Agent|3a| Updater"; threshold: type limit, count 3, seconds 300, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2003584; classtype:trojan-activity; sid:2003584; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Suspicious User-Agent (Updater)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2003584

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012909
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Fragment (WORKED)"; flow:established,to_server; content:"WORKED"; http_header; pcre:"/User-Agent\x3a[^\n]+WORKED/H"; classtype:trojan-activity; sid:2012909; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_05_31, updated_at 2020_04_20;)
` 

Name : **Suspicious User-Agent Fragment (WORKED)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2020-04-20

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013725
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Win32/OnLineGames User-Agent (Revolution Win32)"; flow:established,to_server; content:"User-Agent|3A 20|Revolution|20 28|Win32|29|"; http_header; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013725; rev:2; metadata:created_at 2011_09_30, updated_at 2017_10_30;)
` 

Name : **Win32/OnLineGames User-Agent (Revolution Win32)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-30

Last modified date : 2017-10-30

Rev version : 2

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010906
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS badly formatted User-Agent string (no closing parenthesis)"; flow:established,to_server; content:"User-Agent|3a| Mozilla/4.0 (compatible|3b| "; http_header; content:!")|0d 0a|"; within:100; http_header; pcre:"/\(compatible[^\)]+\n/"; reference:url,doc.emergingthreats.net/2010906; classtype:bad-unknown; sid:2010906; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **badly formatted User-Agent string (no closing parenthesis)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2010906

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012607
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Lowercase User-Agent header purporting to be MSIE"; flow:established,to_server; content:"user-agent|3a 20|Mozilla/4.0|20|(compatible|3b 20|MSIE|20|"; http_header; content:!"|0d 0a|VIA|3a 20|"; http_header; classtype:trojan-activity; sid:2012607; rev:4; metadata:created_at 2011_03_30, updated_at 2011_03_30;)
` 

Name : **Lowercase User-Agent header purporting to be MSIE** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-30

Last modified date : 2011-03-30

Rev version : 4

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003385
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS sgrunt Dialer User Agent (sgrunt)"; flow:to_server,established; content:"sgrunt"; fast_pattern:only; http_header; pcre:"/User-Agent\:[^\n]+sgrunt/Hi"; reference:url,www3.ca.com/securityadvisor/pest/pest.aspx?id=453096347; reference:url,doc.emergingthreats.net/2003385; classtype:trojan-activity; sid:2003385; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **sgrunt Dialer User Agent (sgrunt)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www3.ca.com/securityadvisor/pest/pest.aspx?id=453096347|url,doc.emergingthreats.net/2003385

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012249
`alert http $HOME_NET 1024: -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious Win32 User Agent"; flow:to_server,established; content:"Win32"; nocase; depth:5; http_user_agent; classtype:trojan-activity; sid:2012249; rev:4; metadata:created_at 2011_02_01, updated_at 2011_02_01;)
` 

Name : **Suspicious Win32 User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-01

Last modified date : 2011-02-01

Rev version : 4

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016904
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-Agent (ChilkatUpload)"; flow:to_server,established; content:"ChilkatUpload"; depth:13; http_user_agent; nocase; reference:url,chilkatsoft.com; classtype:trojan-activity; sid:2016904; rev:3; metadata:created_at 2013_05_21, updated_at 2013_05_21;)
` 

Name : **User-Agent (ChilkatUpload)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,chilkatsoft.com

CVE reference : Not defined

Creation date : 2013-05-21

Last modified date : 2013-05-21

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013033
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS EmailSiphon Suspicious User-Agent Outbound"; flow:established,to_server; content:"EmailSiphon"; nocase; http_user_agent; depth:11; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013033; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_06_14, updated_at 2016_07_01;)
` 

Name : **EmailSiphon Suspicious User-Agent Outbound** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-14

Last modified date : 2016-07-01

Rev version : 3

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017067
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious user agent (Google page)"; flow:to_server,established; content:"Google page"; depth:11; http_user_agent; classtype:trojan-activity; sid:2017067; rev:5; metadata:created_at 2011_05_31, updated_at 2011_05_31;)
` 

Name : **Suspicious user agent (Google page)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-31

Last modified date : 2011-05-31

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017949
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET USER_AGENTS FOCA User-Agent"; flow:established,to_server; content:"GET"; http_method; content:"FOCA"; depth:4; http_user_agent; fast_pattern; content:!"Referer|3a 20|"; http_header; content:!"Accept|3a 20|"; http_header; reference:url,blog.bannasties.com/2013/08/vulnerability-scans/; classtype:attempted-recon; sid:2017949; rev:5; metadata:created_at 2014_01_09, updated_at 2014_01_09;)
` 

Name : **FOCA User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,blog.bannasties.com/2013/08/vulnerability-scans/

CVE reference : Not defined

Creation date : 2014-01-09

Last modified date : 2014-01-09

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018279
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS MtGox Leak wallet stealer UA"; flow:established,to_server; content:"MtGoxBackOffice"; depth:15; http_user_agent; metadata: former_category CURRENT_EVENTS; reference:url,www.securelist.com/en/blog/8196/Analysis_of_Malware_from_the_MtGox_leak_archive; reference:md5,c4e99fdcd40bee6eb6ce85167969348d; classtype:trojan-activity; sid:2018279; rev:3; metadata:created_at 2014_03_14, updated_at 2017_11_28;)
` 

Name : **MtGox Leak wallet stealer UA** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.securelist.com/en/blog/8196/Analysis_of_Malware_from_the_MtGox_leak_archive|md5,c4e99fdcd40bee6eb6ce85167969348d

CVE reference : Not defined

Creation date : 2014-03-14

Last modified date : 2017-11-28

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016903
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (DownloadMR)"; flow:to_server,established; content:"DownloadMR"; nocase; depth:10; http_user_agent; reference:url,www.virustotal.com/en/file/93236b781e147e3ac983be1374a5f807fabd27ee2b92e6d99e293a6eb070ac2b/analysis/; reference:md5,0da0d8e664f44400c19898b4c9e71456; classtype:trojan-activity; sid:2016903; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2013_05_21, updated_at 2016_07_01;)
` 

Name : **Suspicious User-Agent (DownloadMR)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,www.virustotal.com/en/file/93236b781e147e3ac983be1374a5f807fabd27ee2b92e6d99e293a6eb070ac2b/analysis/|md5,0da0d8e664f44400c19898b4c9e71456

CVE reference : Not defined

Creation date : 2013-05-21

Last modified date : 2016-07-01

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003335
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS 2search.org User Agent (2search)"; flow:to_server,established; content:"2search"; http_user_agent; fast_pattern:only; reference:url,doc.emergingthreats.net/2003335; classtype:trojan-activity; sid:2003335; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **2search.org User Agent (2search)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2003335

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008142
`#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET USER_AGENTS Vapsup User-Agent (doshowmeanad loader v2.1)"; flow:to_server,established; content:"User-Agent|3a| doshowmeanad "; http_header; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008142; classtype:trojan-activity; sid:2008142; rev:5; metadata:created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Vapsup User-Agent (doshowmeanad loader v2.1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008142

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010721
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious Non-Escaping backslash in User-Agent Outbound"; flow:established,to_server; content:"|5C|"; http_user_agent; depth:200; content:!"|5C|Citrix|5C|ICA Client|5C|"; nocase; http_user_agent; pcre:"/User-Agent\x3a.*[^\x5c]\x5c[^\x5c\x3d\x2f\x3b\x28\x29]/Hi"; metadata: former_category USER_AGENTS; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec14.html; reference:url,mws.amazon.com/docs/devGuide/UserAgent.html; classtype:bad-unknown; sid:2010721; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Suspicious Non-Escaping backslash in User-Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec14.html|url,mws.amazon.com/docs/devGuide/UserAgent.html

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010722
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET USER_AGENTS Suspicious Non-Escaping backslash in User-Agent Inbound"; flow:established,to_server; content:"|5C|"; http_user_agent; depth:200; content:!"|5C|Citrix|5C|ICA Client|5C|"; nocase; http_user_agent; pcre:"/User-Agent\:.*[^\x5c]\x5c[^\x5c\x3d\x2f\x3b\x28\x29]/Hi"; metadata: former_category USER_AGENTS; reference:url,www.w3.org/Protocols/rfc2616/rfc2616-sec14.html; reference:url,mws.amazon.com/docs/devGuide/UserAgent.html; reference:url,doc.emergingthreats.net/2010722; classtype:bad-unknown; sid:2010722; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Suspicious Non-Escaping backslash in User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.w3.org/Protocols/rfc2616/rfc2616-sec14.html|url,mws.amazon.com/docs/devGuide/UserAgent.html|url,doc.emergingthreats.net/2010722

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010697
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET USER_AGENTS Suspicious User-Agent Beginning with digits - Likely spyware/trojan"; flow:established,to_server; content:"|0d 0a|User-Agent|3a| "; content:!"|0d 0a|User-Agent|3a| Mozilla/"; pcre:"/^\d+/V"; content:!"liveupdate.symantecliveupdate.com|0d 0a|"; http_header; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/2010697; classtype:trojan-activity; sid:2010697; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Suspicious User-Agent Beginning with digits - Likely spyware/trojan** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2010697

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 8

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023197
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Microsoft Edge on Windows 10 SET"; flow:established,to_server; content:"Windows NT 10."; http_user_agent; content:"Edge/12."; http_user_agent; distance:0; fast_pattern; flowbits:set,ET_EDGE_UA; flowbits:noalert; metadata: former_category USER_AGENTS; classtype:misc-activity; sid:2023197; rev:4; metadata:affected_product Microsoft_Edge_Browser, deployment Perimeter, tag User_Agent, signature_severity Informational, created_at 2016_09_13, performance_impact Low, updated_at 2017_05_10;)
` 

Name : **Microsoft Edge on Windows 10 SET** 

Attack target : Not defined

Description : Not defined

Tags : User_Agent

Affected products : Microsoft_Edge_Browser

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-09-13

Last modified date : 2017-05-10

Rev version : 4

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2024897
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Go HTTP Client User-Agent"; flow:established,to_server; content:"Go-http-client"; nocase; http_user_agent; fast_pattern; metadata: former_category USER_AGENTS; classtype:misc-activity; sid:2024897; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_10_23, updated_at 2017_10_23;)
` 

Name : **Go HTTP Client User-Agent** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-10-23

Last modified date : 2017-10-23

Rev version : 1

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007808
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Cashpoint.com Related checkin User-Agent (inetinst)"; flow:established,to_server; content:"User-Agent|3a| inetinst|0d 0a|"; http_header; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007808; classtype:trojan-activity; sid:2007808; rev:7; metadata:created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Cashpoint.com Related checkin User-Agent (inetinst)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007808

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007810
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Cashpoint.com Related checkin User-Agent (okcpmgr)"; flow:established,to_server; content:"User-Agent|3a| okcpmgr|0d 0a|"; http_header; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007810; classtype:trojan-activity; sid:2007810; rev:7; metadata:created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Cashpoint.com Related checkin User-Agent (okcpmgr)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007810

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008046
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Rf-cheats.ru Trojan Related User-Agent (RFRudokop v.1.1 account verification)"; flow:to_server,established; content:"RFRudokop"; http_user_agent; depth:9; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008046; classtype:trojan-activity; sid:2008046; rev:8; metadata:created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Rf-cheats.ru Trojan Related User-Agent (RFRudokop v.1.1 account verification)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008046

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008253
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (chek)"; flow:to_server,established; content:"chek"; depth:4; http_user_agent; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008253; classtype:trojan-activity; sid:2008253; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (chek)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008253

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008259
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (AutoHotkey)"; flow:to_server,established; content:"AutoHotkey"; http_user_agent; depth:10; threshold:type limit,count 2,track by_src,seconds 300; content:!".ahk4.net|0d 0a|"; http_header; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008259; classtype:trojan-activity; sid:2008259; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (AutoHotkey)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008259

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008276
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (contains loader)"; flow:to_server,established; content:"User-Agent|3a| "; http_header; content:" loader"; fast_pattern; within:100; http_header; pcre:"/User-Agent\x3a[^\n]+loader/iH"; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008276; classtype:trojan-activity; sid:2008276; rev:15; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (contains loader)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008276

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 15

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008378
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ErrCode)"; flow:established,to_server; content:"ErrCode"; http_user_agent; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008378; classtype:trojan-activity; sid:2008378; rev:12; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (ErrCode)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008378

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 12

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008608
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS WinFixer Trojan Related User-Agent (ElectroSun)"; flow:established,to_server; content:"User-Agent|3a| ElectroSun "; http_header; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008608; classtype:trojan-activity; sid:2008608; rev:9; metadata:created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **WinFixer Trojan Related User-Agent (ElectroSun)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008608

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009537
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Loands) - Possible Trojan Downloader GET Request"; flow:established,to_server; content:"User-Agent\: Loands|0d 0a|"; http_header; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009537; classtype:trojan-activity; sid:2009537; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, tag Trojan_Downloader, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (Loands) - Possible Trojan Downloader GET Request** 

Attack target : Client_Endpoint

Description : A Trojan-Downloader is a type of malware that is responsible for loading and facilitating the continued proliferation of further payloads upon the victim machine. Typically, Trojan-Downloaders will ensure further infection is successful but reporting a successful install, modifying system settings to ensure future malware can be installed/executed without issue, and enable persistency mechanisms for long term infection. Windows is the most commonly observed platform for this type of infection, however, it is not limited-- Macintosh OS X and Linux are also potential targets for compromise.
Valid Trojan-Downloader activity can include network connectivity to a command and control server to report successful infection on a victim machine. Typically, machines impacted with a Trojan-Downloader will have several system settings modified, such as modifications to the Registry where malicious entries may be made. Additionally, the download of a second-stage payload may occur once the original malware has ran. Trojan-Downloaders have been observed with the ability to exfiltrate sensitive data. Confirmation of hostile IP addresses or domains observed with Trojan-Downloader activity may take place in the ET Intelligence portal.
From a network perspective, malware that falls under the Trojan-Downloader has been observed performing activity that would trigger several Emerging Threats INFO, POLICY, and TROJAN style alerts, such as checking an external IP address, the presence of a downloaded executable, or a suspicious HTTP POST to a server. This combination of Trojan-Downloader alerts, as well as complimentary INFO, POLICY, or TROJAN alerts, would warrant an immediate follow up for a compromised workstation.

Tags : Trojan_Downloader, User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009537

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 8

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009538
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ms_ie) - Crypt.ZPACK Gen Trojan Downloader GET Request"; flow:established,to_server; content:"User-Agent\: ms_ie|0d 0a|"; http_header; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009538; classtype:trojan-activity; sid:2009538; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, tag Trojan_Downloader, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (ms_ie) - Crypt.ZPACK Gen Trojan Downloader GET Request** 

Attack target : Client_Endpoint

Description : A Trojan-Downloader is a type of malware that is responsible for loading and facilitating the continued proliferation of further payloads upon the victim machine. Typically, Trojan-Downloaders will ensure further infection is successful but reporting a successful install, modifying system settings to ensure future malware can be installed/executed without issue, and enable persistency mechanisms for long term infection. Windows is the most commonly observed platform for this type of infection, however, it is not limited-- Macintosh OS X and Linux are also potential targets for compromise.
Valid Trojan-Downloader activity can include network connectivity to a command and control server to report successful infection on a victim machine. Typically, machines impacted with a Trojan-Downloader will have several system settings modified, such as modifications to the Registry where malicious entries may be made. Additionally, the download of a second-stage payload may occur once the original malware has ran. Trojan-Downloaders have been observed with the ability to exfiltrate sensitive data. Confirmation of hostile IP addresses or domains observed with Trojan-Downloader activity may take place in the ET Intelligence portal.
From a network perspective, malware that falls under the Trojan-Downloader has been observed performing activity that would trigger several Emerging Threats INFO, POLICY, and TROJAN style alerts, such as checking an external IP address, the presence of a downloaded executable, or a suspicious HTTP POST to a server. This combination of Trojan-Downloader alerts, as well as complimentary INFO, POLICY, or TROJAN alerts, would warrant an immediate follow up for a compromised workstation.

Tags : Trojan_Downloader, User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009538

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 6

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009547
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Forthgoner) - Possible Trojan Downloader GET Request"; flow:established,to_server;  content:"User-Agent\: Forthgoner|0d 0a|"; http_header; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009547; classtype:trojan-activity; sid:2009547; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, tag Trojan_Downloader, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (Forthgoner) - Possible Trojan Downloader GET Request** 

Attack target : Client_Endpoint

Description : A Trojan-Downloader is a type of malware that is responsible for loading and facilitating the continued proliferation of further payloads upon the victim machine. Typically, Trojan-Downloaders will ensure further infection is successful but reporting a successful install, modifying system settings to ensure future malware can be installed/executed without issue, and enable persistency mechanisms for long term infection. Windows is the most commonly observed platform for this type of infection, however, it is not limited-- Macintosh OS X and Linux are also potential targets for compromise.
Valid Trojan-Downloader activity can include network connectivity to a command and control server to report successful infection on a victim machine. Typically, machines impacted with a Trojan-Downloader will have several system settings modified, such as modifications to the Registry where malicious entries may be made. Additionally, the download of a second-stage payload may occur once the original malware has ran. Trojan-Downloaders have been observed with the ability to exfiltrate sensitive data. Confirmation of hostile IP addresses or domains observed with Trojan-Downloader activity may take place in the ET Intelligence portal.
From a network perspective, malware that falls under the Trojan-Downloader has been observed performing activity that would trigger several Emerging Threats INFO, POLICY, and TROJAN style alerts, such as checking an external IP address, the presence of a downloaded executable, or a suspicious HTTP POST to a server. This combination of Trojan-Downloader alerts, as well as complimentary INFO, POLICY, or TROJAN alerts, would warrant an immediate follow up for a compromised workstation.

Tags : Trojan_Downloader, User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009547

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 6

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012310
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Si25f_302 User-Agent"; flow:established,to_server; content:"Si25"; http_user_agent; depth:4; metadata: former_category TROJAN; classtype:trojan-activity; sid:2012310; rev:6; metadata:created_at 2011_02_14, updated_at 2017_10_30;)
` 

Name : **Si25f_302 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-14

Last modified date : 2017-10-30

Rev version : 6

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012586
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Im Luo"; flow:established,to_server; content:"User-Agent|3A| Im|27|Luo"; http_header; metadata: former_category TROJAN; classtype:trojan-activity; sid:2012586; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_03_28, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent Im Luo** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-28

Last modified date : 2017-10-30

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012959
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS MacShield User-Agent Likely Malware"; flow:established,to_server; content:"User-Agent|3a 20|MacShield"; http_header; metadata: former_category TROJAN; reference:url,blog.spiderlabs.com/2011/06/analysis-and-evolution-of-macdefender-os-x-fake-av-scareware.html; classtype:trojan-activity; sid:2012959; rev:4; metadata:created_at 2011_06_08, updated_at 2017_10_30;)
` 

Name : **MacShield User-Agent Likely Malware** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.spiderlabs.com/2011/06/analysis-and-evolution-of-macdefender-os-x-fake-av-scareware.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2017-10-30

Rev version : 4

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013512
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MadeByLc)"; flow:established,to_server; content:"User-Agent|3A 20|MadeBy"; http_header; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013512; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_08_31, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (MadeByLc)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-31

Last modified date : 2017-10-30

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013724
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS W32/OnlineGames User-Agent (LockXLS)"; flow:established,to_server; content:"User-Agent|3A 20|LockXLS"; http_header; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013724; rev:3; metadata:created_at 2011_09_30, updated_at 2017_10_30;)
` 

Name : **W32/OnlineGames User-Agent (LockXLS)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-30

Last modified date : 2017-10-30

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013880
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (FULLSTUFF)"; flow: established,to_server; content:"User-Agent|3A| FULLSTUFF"; nocase; http_header; metadata: former_category TROJAN; reference:url,threatexpert.com/reports.aspx?find=mrb.mail.ru; classtype:trojan-activity; sid:2013880; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_11_08, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (FULLSTUFF)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,threatexpert.com/reports.aspx?find=mrb.mail.ru

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2017-10-30

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018608
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HardCore Software For)"; flow:to_server,established; content:"HardCore Software For"; depth:21; http_user_agent; nocase; metadata: former_category TROJAN; classtype:trojan-activity; sid:2018608; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_07_06, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (HardCore Software For)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-06

Last modified date : 2017-10-30

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008073
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (App4)"; flow:to_server,established; content:"App"; http_user_agent; depth:3; fast_pattern; pcre:"/^\d/VR"; content:!"liveupdate.symantecliveupdate.com"; http_host; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008073; classtype:trojan-activity; sid:2008073; rev:15; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_11_17;)
` 

Name : **Suspicious User-Agent (App4)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008073

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-11-17

Rev version : 15

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2005320
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MyAgent)"; flow:to_server,established; content:"MyAgent"; http_user_agent; depth:7; nocase; fast_pattern; content:!"driverdl.lenovo.com.cn"; http_host; content:!"www.google-analytics.com"; http_header; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2005320; classtype:trojan-activity; sid:2005320; rev:14; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_11_17;)
` 

Name : **Suspicious User-Agent (MyAgent)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2005320

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-11-17

Rev version : 14

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012491
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Presto)"; flow:established,to_server; content:"Opera/10.60 Presto/2.2.30"; http_user_agent; http_header_names; content:!"Accept"; metadata: former_category TROJAN; classtype:trojan-activity; sid:2012491; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_03_11, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (Presto)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-11

Last modified date : 2017-10-30

Rev version : 8

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021384
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS WildTangent User-Agent (WT Games App)"; flow:established,to_server; content:"|0d 0a|WT-User-Agent|3a 20|WT|20|Games|20|App|20|"; http_header; classtype:policy-violation; sid:2021384; rev:2; metadata:created_at 2015_07_06, updated_at 2015_07_06;)
` 

Name : **WildTangent User-Agent (WT Games App)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-07-06

Last modified date : 2015-07-06

Rev version : 2

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009512
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Session) - Possible Trojan-Clicker"; flow:established,to_server; content:"Session"; http_user_agent; depth:7; isdataat:!1,relative; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009512; classtype:trojan-activity; sid:2009512; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent (Session) - Possible Trojan-Clicker** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009512

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012278
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Our_Agent)"; flow:established,to_server; content:"Our_Agent"; http_user_agent; classtype:trojan-activity; sid:2012278; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_02_03, updated_at 2016_07_01;)
` 

Name : **Suspicious User-Agent (Our_Agent)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-03

Last modified date : 2016-07-01

Rev version : 6

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008184
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Installer)"; flow:established,to_server; content:"Installer"; http_user_agent; depth:9; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008184; classtype:trojan-activity; sid:2008184; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent (Installer)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008184

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013178
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Long Fake wget 3.0 User-Agent Detected"; flow:established,to_server; content:"wget 3.0"; http_user_agent; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013178; rev:5; metadata:created_at 2011_07_04, updated_at 2017_10_30;)
` 

Name : **Long Fake wget 3.0 User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-04

Last modified date : 2017-10-30

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013391
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Ufasoft bitcoin Related User-Agent"; flow:established,to_server; content:"Ufasoft"; http_user_agent; depth:7; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013391; rev:5; metadata:created_at 2011_08_10, updated_at 2017_10_30;)
` 

Name : **Ufasoft bitcoin Related User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-10

Last modified date : 2017-10-30

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003657
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MSIE)"; flow:to_server,established; content:"MSIE"; http_user_agent; depth:4; threshold: type limit, count 2, track by_src, seconds 300; content:!"www.msftncsi.com"; http_host; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2003657; classtype:trojan-activity; sid:2003657; rev:18; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (MSIE)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003657

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 18

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012619
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Mozilla/3.0"; flow:established,to_server; content:"Mozilla/3.0"; fast_pattern; http_user_agent; depth:11; isdataat:!1,relative; classtype:trojan-activity; sid:2012619; rev:7; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_03_31, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent Mozilla/3.0** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2019-09-28

Rev version : 8

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008603
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (RLMultySocket)"; flow:established,to_server; content:"RLMultySocket"; http_user_agent; depth:13; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008603; classtype:trojan-activity; sid:2008603; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent Detected (RLMultySocket)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008603

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013508
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Downloader User-Agent HTTPGET"; flow:established,to_server; content:"HTTPGET"; depth:7; http_user_agent; content:!"autodesk.com"; http_host; isdataat:!1,relative; content:!"rsa.com"; http_host; isdataat:!1,relative; content:!"consumersentinel.gov"; http_host; isdataat:!1,relative; content:!"technet.microsoft.com"; http_host; isdataat:!1,relative; content:!"metropolis.com"; http_host; isdataat:!1,relative; content:!"www.catalog.update.microsoft.com"; http_host; isdataat:!1,relative; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013508; rev:12; metadata:created_at 2011_08_31, updated_at 2019_09_28;)
` 

Name : **Downloader User-Agent HTTPGET** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-31

Last modified date : 2019-09-28

Rev version : 13

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025456
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (=Mozilla)"; flow:established,to_server; content:"User-Agent|3a|=Mozilla/5"; http_header; fast_pattern; metadata: former_category USER_AGENTS; classtype:trojan-activity; sid:2025456; rev:2; metadata:affected_product Web_Browsers, attack_target Client_and_Server, deployment Perimeter, signature_severity Major, created_at 2018_03_27, performance_impact Low, updated_at 2018_04_03;)
` 

Name : **Suspicious User-Agent (=Mozilla)** 

Attack target : Client_and_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-03-27

Last modified date : 2018-04-03

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2011276
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (InfoBot)"; flow:to_server,established; content:"InfoBot"; http_user_agent; nocase; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2011276; classtype:trojan-activity; sid:2011276; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2017_10_30;)
` 

Name : **Suspicious User-Agent (InfoBot)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2011276

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-10-30

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025889
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS VPNFilter Related UA (Gemini/2.0)"; flow:established,to_server; content:"Gemini/2.0"; http_user_agent; depth:10; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,twitter.com/m0rb/status/1021626709307805696; classtype:trojan-activity; sid:2025889; rev:1; metadata:attack_target Server, deployment Perimeter, signature_severity Major, created_at 2018_07_25, malware_family VPNFilter, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **VPNFilter Related UA (Gemini/2.0)** 

Attack target : Server

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,twitter.com/m0rb/status/1021626709307805696

CVE reference : Not defined

Creation date : 2018-07-25

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : VPNFilter

Type : SID

Performance Impact : Low

# 2025890
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS VPNFilter Related UA (Hakai/2.0)"; flow:established,to_server; content:"Hakai/2.0"; http_user_agent; depth:9; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,twitter.com/m0rb/status/1021626709307805696; classtype:trojan-activity; sid:2025890; rev:2; metadata:attack_target Server, deployment Perimeter, signature_severity Major, created_at 2018_07_25, malware_family VPNFilter, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **VPNFilter Related UA (Hakai/2.0)** 

Attack target : Server

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,twitter.com/m0rb/status/1021626709307805696

CVE reference : Not defined

Creation date : 2018-07-25

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : VPNFilter

Type : SID

Performance Impact : Low

# 2007821
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HTTP_CONNECT_)"; flow:established,to_server; content:"HTTP_Connect_"; http_user_agent; depth:13; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/bin/view/Main/2007821; classtype:bad-unknown; sid:2007821; rev:7; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Spyware_User_Agent, signature_severity Minor, created_at 2010_07_30, updated_at 2018_08_15;)
` 

Name : **Suspicious User-Agent (HTTP_CONNECT_)** 

Attack target : Client_Endpoint

Description : Spyware User-Agent signatures are a class of alerts that specifically look for known Spyware User-Agent strings that are leveraged by machines installed with potentially unwanted applications.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware / Spyware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware / Spyware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Spyware often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Spyware User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Spyware is a grey area, and isn't necessarily "malicious" depending on the observer's opinion.

These signatures are a good indicator of a compromised client, server, phone, etc.

Tags : Spyware_User_Agent

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007821

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2018-08-15

Rev version : 7

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026101
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS MSIL/Peppy User-Agent"; flow:established,to_server; content:"onedru/"; http_user_agent; depth:7; isdataat:!1,relative; fast_pattern; metadata: former_category USER_AGENTS; reference:md5,ebffb046d0e12b46ba5f27c0176b01c5; classtype:trojan-activity; sid:2026101; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2018_09_07, malware_family Peppy, performance_impact Moderate, updated_at 2019_09_28;)
` 

Name : **MSIL/Peppy User-Agent** 

Attack target : Client_Endpoint

Description : This will alert on a user-agent observed performing a connectivity check associated with MSIL/Peppy activity.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,ebffb046d0e12b46ba5f27c0176b01c5

CVE reference : Not defined

Creation date : 2018-09-07

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Peppy

Type : SID

Performance Impact : Moderate

# 2026428
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS VPNFilter Related UA (curl53)"; flow:established,to_server; content:"curl53"; http_user_agent; depth:6; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,blog.talosintelligence.com/2018/09/vpnfilter-part-3.html; classtype:trojan-activity; sid:2026428; rev:2; metadata:affected_product Linux, attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2018_10_01, malware_family VPNFilter, updated_at 2019_09_28;)
` 

Name : **VPNFilter Related UA (curl53)** 

Attack target : Networking_Equipment

Description : Alerts on VPNFilter hardcoded UA

Tags : Not defined

Affected products : Linux

Alert Classtype : trojan-activity

URL reference : url,blog.talosintelligence.com/2018/09/vpnfilter-part-3.html

CVE reference : Not defined

Creation date : 2018-10-01

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : VPNFilter

Type : SID

Performance Impact : Not defined

# 2026519
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Windows XP)"; flow:to_server,established; content:"Windows XP"; depth:10; http_user_agent; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026519; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_10_18, updated_at 2018_10_18;)
` 

Name : **Suspicious User-Agent (Windows XP)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-18

Last modified date : 2018-10-18

Rev version : 1

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026520
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Windows 8)"; flow:to_server,established; content:"Windows 8"; depth:9; http_user_agent; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026520; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_10_18, updated_at 2018_10_18;)
` 

Name : **Suspicious User-Agent (Windows 8)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-18

Last modified date : 2018-10-18

Rev version : 1

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026522
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Windows 7)"; flow:to_server,established; content:"Windows 7"; depth:9; http_user_agent; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026522; rev:1; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_10_18, updated_at 2018_10_18;)
` 

Name : **Suspicious User-Agent (Windows 7)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-18

Last modified date : 2018-10-18

Rev version : 1

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026521
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Windows 10)"; flow:to_server,established; content:"Windows 10"; depth:10; http_user_agent; content:!"google-analytics.com"; http_host; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2026521; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2018_10_18, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent (Windows 10)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-10-18

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026558
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious UA Observed (IEhook)"; flow:established,to_server; content:"IEhook"; http_user_agent; depth:6; isdataat:!1,relative; fast_pattern; metadata: former_category USER_AGENTS; reference:md5,f0483493bcb352bd2f474b52f3b2f273; classtype:trojan-activity; sid:2026558; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Minor, created_at 2018_10_26, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious UA Observed (IEhook)** 

Attack target : Client_Endpoint

Description : Alerts on a HTTP request containing a suspicious non-standard User-Agent.

Tags : User_Agent

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : md5,f0483493bcb352bd2f474b52f3b2f273

CVE reference : Not defined

Creation date : 2018-10-26

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026850
`alert http any any -> $HOME_NET any (msg:"ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement"; flow:established,to_server; content:"Microsoft|20|WinRM|20|Client"; http_user_agent; depth:22; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,attack.mitre.org/techniques/T1028/; classtype:bad-unknown; sid:2026850; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Internal, tag WinRM, signature_severity Major, created_at 2019_01_23, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **WinRM User Agent Detected - Possible Lateral Movement** 

Attack target : Client_and_Server

Description : Alerts on usage of Windows Remote Management, used by APT27 and Cobalt Strike for lateral movement/remote payload execution.

Tags : WinRM

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,attack.mitre.org/techniques/T1028/

CVE reference : Not defined

Creation date : 2019-01-23

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026883
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Peppy/KeeOIL Google User-Agent (google/dance)"; flow:established,to_server; content:"google/dance"; http_user_agent; depth:14; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,www.malcrawler.com/team-simbaa-targets-indian-government-using-united-nations-military-observers-themed-malware-nicked-named-keeoil/; classtype:trojan-activity; sid:2026883; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_05, malware_family Peppy, malware_family KeeOIL, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Peppy/KeeOIL Google User-Agent (google/dance)** 

Attack target : Client_Endpoint

Description : Alerts on an HTTP request containing a custom User-Agent string used by KeeOIL/Peppy malware.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,www.malcrawler.com/team-simbaa-targets-indian-government-using-united-nations-military-observers-themed-malware-nicked-named-keeoil/

CVE reference : Not defined

Creation date : 2019-02-05

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Peppy

Type : SID

Performance Impact : Low

# 2026885
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Peppy/KeeOIL User-Agent (ekeoil)"; flow:established,to_server; content:"ekeoil/"; http_user_agent; depth:7; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,www.malcrawler.com/team-simbaa-targets-indian-government-using-united-nations-military-observers-themed-malware-nicked-named-keeoil/; classtype:trojan-activity; sid:2026885; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_05, malware_family Peppy, malware_family KeeOIL, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Peppy/KeeOIL User-Agent (ekeoil)** 

Attack target : Client_Endpoint

Description : Alerts on an HTTP request containing a custom User-Agent string used by KeeOIL/Peppy malware.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,www.malcrawler.com/team-simbaa-targets-indian-government-using-united-nations-military-observers-themed-malware-nicked-named-keeoil/

CVE reference : Not defined

Creation date : 2019-02-05

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Peppy

Type : SID

Performance Impact : Low

# 2026898
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (SomeTimes)"; flow:established,to_server; content:"SomeTimes"; http_user_agent; depth:9; isdataat:!1,relative; fast_pattern; metadata: former_category USER_AGENTS; reference:md5,a86d4e17389a37bfc291f4a8da51a9b8; classtype:trojan-activity; sid:2026898; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Minor, created_at 2019_02_11, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious User-Agent (SomeTimes)** 

Attack target : Client_Endpoint

Description : Alerts on a HTTP request containing a suspicious custom User-Agent string of 'SomeTimes'.

Tags : User_Agent

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,a86d4e17389a37bfc291f4a8da51a9b8

CVE reference : Not defined

Creation date : 2019-02-11

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026914
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS SFML User-Agent (libsfml-network) "; flow:established,to_server; content:"libsfml-network/"; http_user_agent; depth:16; fast_pattern; metadata: former_category USER_AGENTS; reference:url,github.com/SFML; classtype:trojan-activity; sid:2026914; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_02_14, performance_impact Low, updated_at 2019_02_14;)
` 

Name : **SFML User-Agent (libsfml-network) ** 

Attack target : Client_Endpoint

Description : Alerts on a HTTP request containing a User-Agent from the SFML library which can be used by various programming languages to access windowing, graphics, audio and network.  This library has also been used by the Molerats APT in several campaigns.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,github.com/SFML

CVE reference : Not defined

Creation date : 2019-02-14

Last modified date : 2019-02-14

Rev version : 1

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027045
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Clever Internet Suite)"; flow:established,to_server; content:"Clever Internet Suite"; http_user_agent; metadata: former_category USER_AGENTS; classtype:trojan-activity; sid:2027045; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, signature_severity Major, created_at 2019_03_05, performance_impact Low, updated_at 2019_03_05;)
` 

Name : **Suspicious User-Agent (Clever Internet Suite)** 

Attack target : Not defined

Description : Alerts on a suspicious custom User-Agent string observed in malware campaigns.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 1

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027142
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Mozilla 6.0)"; flow:established,to_server; content:"Mozilla 6.0"; http_user_agent; depth:11; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2027142; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_01, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (Mozilla 6.0)** 

Attack target : Client_Endpoint

Description : This will alert on a suspicious non-standard user-agent string, sometimes observed in malware traffic.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-01

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027219
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS ESET Installer"; flow:established,to_server; content:"ESET Installer"; http_user_agent; depth:14; isdataat:!1,relative; threshold: type limit, track by_src, seconds 180, count 1;  metadata: former_category USER_AGENTS; classtype:policy-violation; sid:2027219; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, tag PUA, signature_severity Minor, created_at 2019_04_17, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **ESET Installer** 

Attack target : Client_Endpoint

Description : Not defined

Tags : PUA

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-17

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027286
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Aria2 User-Agent"; flow:to_server,established; content:"aria2/"; http_user_agent; depth:6; fast_pattern; metadata: former_category USER_AGENTS; reference:url,github.com/aria2/aria2; reference:md5,eb042fe28b8a235286df2c7f4ed1d8a8; classtype:trojan-activity; sid:2027286; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_04_25, updated_at 2019_04_25;)
` 

Name : **Aria2 User-Agent** 

Attack target : Client_Endpoint

Description : Aria2 download client UA, observed download pony among other stealers

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,github.com/aria2/aria2|md5,eb042fe28b8a235286df2c7f4ed1d8a8

CVE reference : Not defined

Creation date : 2019-04-25

Last modified date : 2019-04-25

Rev version : 1

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027390
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent"; flow:established,to_server; content:"MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT"; depth:42; isdataat:!1,relative; nocase; http_user_agent; fast_pattern; metadata: former_category USER_AGENTS; classtype:unknown; sid:2027390; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_05_28, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Microsoft Device Metadata Retrieval Client User-Agent** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-28

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027388
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Node XMLHTTP User-Agent"; flow:established,to_server; content:"node-XMLHttpRequest"; depth:19; isdataat:!1,relative; nocase; http_user_agent; fast_pattern; metadata: former_category USER_AGENTS; classtype:unknown; sid:2027388; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_05_28, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Node XMLHTTP User-Agent** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-28

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027484
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious UA Observed (YourUserAgent)"; flow:established,to_server; content:"YourUserAgent"; http_user_agent; depth:13; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; reference:md5,c1ca718e7304bf28b5c96559cbf69a06; classtype:bad-unknown; sid:2027484; rev:1; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_06_17, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious UA Observed (YourUserAgent)** 

Attack target : Not defined

Description : Alerts on a suspicious custom User-Agent value of 'YourUserAgent', possibly used as a placeholder in commodity malware.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,c1ca718e7304bf28b5c96559cbf69a06

CVE reference : Not defined

Creation date : 2019-06-17

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027503
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Hello, World)"; flow:established,to_server; content:"Hello, World"; http_user_agent; depth:12; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027503; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_06_21, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (Hello, World)** 

Attack target : Client_Endpoint

Description : This will alert on an unusual User-Agent.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-21

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027504
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Hello-World)"; flow:established,to_server; content:"Hello-World"; http_user_agent; depth:11; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027504; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_06_21, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (Hello-World)** 

Attack target : Client_Endpoint

Description : This will alert on an unusual User-Agent.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-21

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027565
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Fake Mozilla User-Agent String Observed (M0zilla)"; flow:established,to_server; content:"M0zilla|2f|"; http_user_agent; depth:8; fast_pattern; content:"."; http_user_agent; distance:1; within:1; metadata: former_category USER_AGENTS; reference:md5,c6c1292bf7dd1573b269afb203134b1d; classtype:trojan-activity; sid:2027565; rev:1; metadata:created_at 2019_06_26, updated_at 2019_06_26;)
` 

Name : **Fake Mozilla User-Agent String Observed (M0zilla)** 

Attack target : Not defined

Description : Alerts on a custom User-Agent string with a zero in place of the 'o' in 'Mozilla'

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,c6c1292bf7dd1573b269afb203134b1d

CVE reference : Not defined

Creation date : 2019-06-26

Last modified date : 2019-06-26

Rev version : 1

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027648
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious UA Observed (Ave, Caesar!)"; flow:established,to_server; content:"Ave,|20|Caesar!"; http_user_agent; depth:12; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027648; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, signature_severity Major, created_at 2019_06_28, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious UA Observed (Ave, Caesar!)** 

Attack target : Not defined

Description : Alerts on a suspicious custom User-Agent string observed in an IP lookup request.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-28

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027649
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (zwt)"; flow:established,to_server; content:"zwt"; http_user_agent; depth:3; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027649; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_07_01, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (zwt)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-01

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027650
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (My Agent)"; flow:established,to_server; content:"My Agent"; http_user_agent; depth:8; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027650; rev:1; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_07_01, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (My Agent)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-01

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027686
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious Custom Firefox UA Observed (Firefox...)"; flow:established,to_server; content:"Firefox..."; http_user_agent; depth:10; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027686; rev:1; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_07_04, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious Custom Firefox UA Observed (Firefox...)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-07-04

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2007880
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-Agent (single dash)"; flow:to_server,established; content:"-"; http_user_agent; depth:1; isdataat:!1,relative; metadata: former_category MALWARE; reference:url,doc.emergingthreats.net/bin/view/Main/2007880; classtype:trojan-activity; sid:2007880; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **User-Agent (single dash)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007880

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027755
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious UA Observed (Quick Macros)"; flow:established,to_server; content:"Quick|20|Macros"; http_user_agent; depth:12; isdataat:!1,relative; metadata: former_category HUNTING; reference:md5,aa682f5d4a17307539a2bc7048be0745; classtype:trojan-activity; sid:2027755; rev:1; metadata:deployment Perimeter, signature_severity Minor, created_at 2019_07_24, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Suspicious UA Observed (Quick Macros)** 

Attack target : Not defined

Description : Alerts on a suspicious User-Agent.

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,aa682f5d4a17307539a2bc7048be0745

CVE reference : Not defined

Creation date : 2019-07-24

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2001891
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (agent)"; flow:established,to_server; content:"agent"; http_user_agent; depth:5; content:!".battle.net"; http_host; content:!".blizzard.com"; http_host; isdataat:!1,relative; content:!"blz"; depth:3; http_host; content:!"cn.patch.battlenet.com.cn"; http_host; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2001891; classtype:trojan-activity; sid:2001891; rev:22; metadata:created_at 2010_07_30, updated_at 2019_09_28;)
` 

Name : **Suspicious User Agent (agent)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001891

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-28

Rev version : 23

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011227
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (NSIS_Inetc (Mozilla))"; flow:established,to_server; content:"NSIS|5f|Inetc|20 28|Mozilla|29|"; http_user_agent; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2011227; classtype:bad-unknown; sid:2011227; rev:6; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2010_07_30, updated_at 2019_08_07;)
` 

Name : **Observed Suspicious UA (NSIS_Inetc (Mozilla))** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2011227

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-07

Rev version : 6

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027833
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious Generic Style UA Observed (My_App)"; flow:established,to_server; content:"My_App"; http_user_agent; depth:6; fast_pattern; isdataat:!1,relative; metadata: former_category HUNTING; reference:md5,2978dbadd8fda7d842298fbd476b47b2; classtype:trojan-activity; sid:2027833; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, created_at 2019_08_09, updated_at 2019_09_28;)
` 

Name : **Suspicious Generic Style UA Observed (My_App)** 

Attack target : Not defined

Description : Alerts on an outbound custom User-Agent string.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : md5,2978dbadd8fda7d842298fbd476b47b2

CVE reference : Not defined

Creation date : 2019-08-09

Last modified date : 2019-09-28

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002400
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (Microsoft Internet Explorer)"; flow:established,to_server; content:"Microsoft Internet Explorer"; depth:28; http_user_agent; content:!"bbc.co.uk"; http_host; content:!"vmware.com"; http_host; content:!"rc.itsupport247.net"; http_host; content:!"msn.com"; http_host; content:!"msn.es"; http_host; content:!"live.com"; http_host; content:!"gocyberlink.com"; http_host; content:!"ultraedit.com"; http_host; content:!"windowsupdate.com"; http_host; content:!"cyberlink.com"; http_host; content:!"lenovo.com"; http_host; content:!"itsupport247.net"; http_host; content:!"msn.co.uk"; http_host; content:!"support.weixin.qq.com"; http_host; threshold:type limit, track by_src, count 2, seconds 360; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2002400; classtype:trojan-activity; sid:2002400; rev:36; metadata:created_at 2010_07_30, updated_at 2019_08_13;)
` 

Name : **Suspicious User Agent (Microsoft Internet Explorer)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002400

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-13

Rev version : 36

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009545
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-Agent (_TEST_)"; flow: to_server,established; content:"_TEST_"; nocase; http_user_agent; metadata: former_category ADWARE_PUP; reference:url,doc.emergingthreats.net/2009545; classtype:unknown; sid:2009545; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **User-Agent (_TEST_)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unknown

URL reference : url,doc.emergingthreats.net/2009545

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027916
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Chrome)"; flow:established,to_server; content:"Chrome"; http_user_agent; depth:6; isdataat:!1,relative; content:"User-Agent|3a 20|Chrome|0d 0a|"; http_header; fast_pattern; metadata: former_category HUNTING; classtype:bad-unknown; sid:2027916; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_08_26, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (Chrome)** 

Attack target : Client_Endpoint

Description : This will alert on the observance of a User-Agent which is suspicious and non-standard which could be indicative of unwanted activity.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-08-26

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2028571
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Absent)"; flow:established,to_server; content:"Absent"; http_user_agent; depth:6; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2028571; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_09_12, performance_impact Low, updated_at 2019_09_28;)
` 

Name : **Observed Suspicious UA (Absent)** 

Attack target : Client_Endpoint

Description : This will alert on a suspicious User-Agent string.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-09-12

Last modified date : 2019-09-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2002078
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS SideStep User-Agent"; flow: to_server,established; content:" SideStep"; fast_pattern; http_header; pcre:"/User-Agent\:[^\n]+SideStep/iH"; reference:url,doc.emergingthreats.net/2002078; reference:url,github.com/chetan51/sidestep/; classtype:misc-activity; sid:2002078; rev:31; metadata:attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Minor, created_at 2010_07_30, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **SideStep User-Agent** 

Attack target : Client_Endpoint

Description : This is an informational signature that identifies user agents with "SideStep".

Tags : User_Agent

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002078|url,github.com/chetan51/sidestep/

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 31

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2012313
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Moxilla"; flow:established,to_server; content:"Moxilla"; http_user_agent; depth:7; classtype:trojan-activity; sid:2012313; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_02_14, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Moxilla** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-14

Last modified date : 2019-10-11

Rev version : 6

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012555
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (VMozilla)"; flow:to_server,established; content:"VMozilla"; http_user_agent; depth:8; nocase; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3aWin32%2fNeeris.BF; reference:url,www.avira.com/en/support-threats-description/tid/6259/tlang/en; classtype:trojan-activity; sid:2012555; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_03_25, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (VMozilla)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3aWin32%2fNeeris.BF|url,www.avira.com/en/support-threats-description/tid/6259/tlang/en

CVE reference : Not defined

Creation date : 2011-03-25

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012695
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS suspicious User Agent (Lotto)"; flow:to_server,established; content:"Lotto"; http_user_agent; depth:5; classtype:trojan-activity; sid:2012695; rev:3; metadata:created_at 2011_04_20, updated_at 2019_10_11;)
` 

Name : **suspicious User Agent (Lotto)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-20

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012761
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious user agent (mdms)"; flow:to_server,established; content:"GET"; http_method; content:"mdms"; http_user_agent; depth:4; isdataat:!1,relative; classtype:trojan-activity; sid:2012761; rev:3; metadata:created_at 2011_05_02, updated_at 2019_10_11;)
` 

Name : **Suspicious user agent (mdms)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-02

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012762
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious user agent (asd)"; flow:to_server,established; content:"GET"; http_method; content:"asd"; nocase; http_user_agent; depth:3; isdataat:!1,relative; classtype:trojan-activity; sid:2012762; rev:3; metadata:created_at 2011_05_03, updated_at 2019_10_11;)
` 

Name : **Suspicious user agent (asd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-05-03

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013032
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET USER_AGENTS EmailSiphon Suspicious User-Agent Inbound"; flow:established,to_server; content:"EmailSiphon"; nocase; http_user_agent; depth:11; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013032; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_06_14, updated_at 2019_10_11;)
` 

Name : **EmailSiphon Suspicious User-Agent Inbound** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-14

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013050
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Binget PHP Library User Agent Outbound"; flow:established,to_server; content:"Binget/"; nocase; http_user_agent; depth:7; reference:url,www.bin-co.com/php/scripts/load/; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013050; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **Binget PHP Library User Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.bin-co.com/php/scripts/load/|url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013052
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS pxyscand/ Suspicious User Agent Outbound"; flow:established,to_server; content:"pxyscand/"; nocase; http_user_agent; depth:9; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013052; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **pxyscand/ Suspicious User Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013054
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS PyCurl Suspicious User Agent Outbound"; flow:established,to_server; content:"PyCurl"; nocase; http_user_agent; depth:6; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013054; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **PyCurl Suspicious User Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2019-10-11

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012734
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent String (AskPartnerCobranding)"; flow:to_server,established; content:"AskPartner"; http_user_agent; depth:10; classtype:trojan-activity; sid:2012734; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_04_28, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent String (AskPartnerCobranding)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-28

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008983
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (BlackSun)"; flow:to_server,established; content:"BlackSun"; nocase; http_user_agent; depth:8; metadata: former_category HUNTING; reference:url,www.bitdefender.com/VIRUS-1000328-en--Trojan.Pws.Wow.NCY.html; reference:url,doc.emergingthreats.net/bin/view/Main/2008983; classtype:trojan-activity; sid:2008983; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User Agent (BlackSun)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.bitdefender.com/VIRUS-1000328-en--Trojan.Pws.Wow.NCY.html|url,doc.emergingthreats.net/bin/view/Main/2008983

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007991
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-Agent (Unknown)"; flow:to_server,established; content:"Unknown"; http_user_agent; depth:7; isdataat:!1,relative; metadata: former_category MALWARE; reference:url,doc.emergingthreats.net/bin/view/Main/2007991; classtype:trojan-activity; sid:2007991; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **User-Agent (Unknown)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007991

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002874
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Metafisher/Goldun User-Agent (z)"; flow:to_server,established; content:"z"; http_user_agent; depth:1; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2002874; classtype:trojan-activity; sid:2002874; rev:16; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Metafisher/Goldun User-Agent (z)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2002874

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 16

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003586
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (WinXP Pro Service Pack 2)"; flow:to_server,established; content:"WinXP Pro Service Pack"; http_user_agent; depth:22; threshold: type limit, count 3, seconds 300, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2003586; classtype:trojan-activity; sid:2003586; rev:14; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (WinXP Pro Service Pack 2)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2003586

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 14

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003622
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent outbound (bot)"; flow:to_server,established; content:"bot/"; http_user_agent; depth:4; nocase; threshold: type limit, count 3, seconds 300, track by_src; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2003622; classtype:trojan-activity; sid:2003622; rev:14; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent outbound (bot)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003622

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 14

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003927
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HTTPTEST) - Seen used by downloaders"; flow:to_server,established; content:"HTTPTEST"; nocase; http_user_agent; depth:8; content:!"PlayStation"; http_header; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2003927; classtype:trojan-activity; sid:2003927; rev:12; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (HTTPTEST) - Seen used by downloaders** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003927

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 12

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003930
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Snatch-System)"; flow:to_server,established; content:"Snatch-System"; nocase; http_user_agent; depth:13; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2003930; classtype:trojan-activity; sid:2003930; rev:13; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Snatch-System)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003930

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 13

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2004443
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS KKtone Suspicious User-Agent (KKTone)"; flow:to_server,established; content:"KKTone"; nocase; http_user_agent; depth:6; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2004443; classtype:trojan-activity; sid:2004443; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **KKtone Suspicious User-Agent (KKTone)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2004443

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006364
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Dialer-967 User-Agent"; flow:to_server,established; content:"del"; http_user_agent; depth:3; isdataat:!1,relative; nocase; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2006364; classtype:trojan-activity; sid:2006364; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Dialer-967 User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2006364

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006365
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MYURL)"; flow:to_server,established; content:"MYURL"; http_user_agent; depth:5; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2006365; classtype:trojan-activity; sid:2006365; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (MYURL)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006365

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006382
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Matcash or related downloader User-Agent Detected"; flow:established,to_server; content:"User-Agent|3a 20|x"; http_header; pcre:"/^x\w\wx\w\w\!x\w\wx\w\wx\w\w/V"; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2006382; classtype:trojan-activity; sid:2006382; rev:11; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Matcash or related downloader User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2006382

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006387
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Downloader User-Agent Detected (Windows Updates Manager|3.12|...)"; flow:established,to_server; content:"Windows Updates Manager|7c|"; http_user_agent; depth:24; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2006387; classtype:trojan-activity; sid:2006387; rev:10; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Downloader User-Agent Detected (Windows Updates Manager|3.12|...)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2006387

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006394
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Downloader User-Agent Detected (ld)"; flow:established,to_server; content:"ld"; http_user_agent; depth:2; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2006394; classtype:trojan-activity; sid:2006394; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Downloader User-Agent Detected (ld)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2006394

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007758
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Eldorado.BHO User-Agent Detected (netcfg)"; flow:established,to_server; content:"GET"; nocase; http_method; content:"netcfg"; http_user_agent; depth:6; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007758; classtype:trojan-activity; sid:2007758; rev:10; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Eldorado.BHO User-Agent Detected (netcfg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007758

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007767
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Pakes User-Agent Detected"; flow:established,to_server; content:"Mozilla/4.7 [en] (WinNT"; http_user_agent; depth:23; fast_pattern; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007767; classtype:trojan-activity; sid:2007767; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Pakes User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007767

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007770
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Tear Application User-Agent Detected"; flow:established,to_server; content:"Tear Application"; http_user_agent; depth:16; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007770; classtype:trojan-activity; sid:2007770; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Tear Application User-Agent Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007770

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008019
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent - Possible Trojan Downloader (https)"; flow:established,to_server; content:"https"; http_user_agent; depth:5; isdataat:!1,relative; nocase; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2008019; classtype:trojan-activity; sid:2008019; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, tag Trojan_Downloader, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent - Possible Trojan Downloader (https)** 

Attack target : Client_Endpoint

Description : A Trojan-Downloader is a type of malware that is responsible for loading and facilitating the continued proliferation of further payloads upon the victim machine. Typically, Trojan-Downloaders will ensure further infection is successful but reporting a successful install, modifying system settings to ensure future malware can be installed/executed without issue, and enable persistency mechanisms for long term infection. Windows is the most commonly observed platform for this type of infection, however, it is not limited-- Macintosh OS X and Linux are also potential targets for compromise.
Valid Trojan-Downloader activity can include network connectivity to a command and control server to report successful infection on a victim machine. Typically, machines impacted with a Trojan-Downloader will have several system settings modified, such as modifications to the Registry where malicious entries may be made. Additionally, the download of a second-stage payload may occur once the original malware has ran. Trojan-Downloaders have been observed with the ability to exfiltrate sensitive data. Confirmation of hostile IP addresses or domains observed with Trojan-Downloader activity may take place in the ET Intelligence portal.
From a network perspective, malware that falls under the Trojan-Downloader has been observed performing activity that would trigger several Emerging Threats INFO, POLICY, and TROJAN style alerts, such as checking an external IP address, the presence of a downloaded executable, or a suspicious HTTP POST to a server. This combination of Trojan-Downloader alerts, as well as complimentary INFO, POLICY, or TROJAN alerts, would warrant an immediate follow up for a compromised workstation.

Tags : Trojan_Downloader, User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008019

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008043
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (c \windows)"; flow:to_server,established; content:"c|3a 5c|"; http_user_agent; depth:3; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/bin/view/Main/2008043; classtype:trojan-activity; sid:2008043; rev:13; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (c \windows)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008043

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 13

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008048
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Version 1.23)"; flow:to_server,established; content:"Version "; http_user_agent; depth:8; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008048; classtype:trojan-activity; sid:2008048; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Version 1.23)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008048

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008084
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Mozilla-web)"; flow:to_server,established; content:"Mozilla-web"; http_user_agent; depth:11; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008084; classtype:trojan-activity; sid:2008084; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Mozilla-web)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008084

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008096
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (INSTALLER)"; flow:to_server,established; content:"INSTALLER"; http_user_agent; depth:9; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008096; classtype:trojan-activity; sid:2008096; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (INSTALLER)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008096

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008097
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (IEMGR)"; flow:to_server,established; content:"IEMGR"; http_user_agent; depth:5; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008097; classtype:trojan-activity; sid:2008097; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (IEMGR)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008097

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008098
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (GOOGLE)"; flow:to_server,established; content:"GOOGLE"; http_user_agent; depth:6; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008098; classtype:trojan-activity; sid:2008098; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (GOOGLE)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008098

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008147
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (RBR)"; flow:to_server,established; content:"RBR"; http_user_agent; depth:3; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008147; classtype:trojan-activity; sid:2008147; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (RBR)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008147

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008159
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Otwycal User-Agent (Downing)"; flow:to_server,established; content:"Downing"; http_user_agent; depth:7; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008159; classtype:trojan-activity; sid:2008159; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Otwycal User-Agent (Downing)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008159

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008181
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MS Internet Explorer)"; flow:to_server,established; content:"MS Internet Explorer"; http_user_agent; depth:20; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008181; classtype:trojan-activity; sid:2008181; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (MS Internet Explorer)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008181

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008199
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (QQ)"; flow:to_server,established; content:"QQ"; http_user_agent; depth:2; isdataat:!1,relative; content:!"|0d 0a|Q-UA|3a 20|"; http_header; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008199; classtype:trojan-activity; sid:2008199; rev:19; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (QQ)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008199

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 19

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008208
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (TestAgent)"; flow:to_server,established; content:"TestAgent"; http_user_agent; depth:9; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008208; classtype:trojan-activity; sid:2008208; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (TestAgent)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008208

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008209
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (SERVER2_03)"; flow:to_server,established; content:"SERVER"; http_user_agent; depth:6; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008209; classtype:trojan-activity; sid:2008209; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (SERVER2_03)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008209

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008211
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (WinProxy)"; flow:to_server,established; content:"WinProxy"; nocase; http_user_agent; depth:8; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008211; classtype:trojan-activity; sid:2008211; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (WinProxy)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008211

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008214
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (sickness29a/0.1)"; flow:to_server,established; content:"sickness"; nocase; http_user_agent; depth:8; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008214; classtype:trojan-activity; sid:2008214; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (sickness29a/0.1)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008214

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008215
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (up2dash updater)"; flow:to_server,established; content:"up2dash"; nocase; http_user_agent; depth:7; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008215; classtype:trojan-activity; sid:2008215; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (up2dash updater)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008215

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008231
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Mozilla 1.02.45 biz)"; flow:to_server,established; content:"Mozilla "; http_user_agent; depth:8; content:" biz|0d 0a|"; within:15; http_header; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008231; classtype:trojan-activity; sid:2008231; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Mozilla 1.02.45 biz)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008231

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008255
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (IE)"; flow:to_server,established; content:"IE"; http_user_agent; depth:2; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008255; classtype:trojan-activity; sid:2008255; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (IE)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008255

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008262
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (WebForm 1)"; flow:to_server,established; content:"WebForm"; http_user_agent; depth:7; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008262; classtype:trojan-activity; sid:2008262; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (WebForm 1)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008262

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008264
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (opera)"; flow:to_server,established; content:"opera"; http_user_agent; depth:5; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008264; classtype:trojan-activity; sid:2008264; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (opera)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008264

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008266
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Zilla)"; flow:to_server,established; content:"Zilla"; http_user_agent; depth:5; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008266; classtype:trojan-activity; sid:2008266; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Zilla)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008266

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008343
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (123)"; flow:to_server,established; content:"123"; http_user_agent; depth:3; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008343; classtype:trojan-activity; sid:2008343; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (123)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008343

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008355
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (angel)"; flow:to_server,established; content:"angel"; http_user_agent; depth:5; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008355; classtype:trojan-activity; sid:2008355; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (angel)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008355

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008361
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Accessing)"; flow:to_server,established; content:"Accessing"; http_user_agent; depth:9; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008361; classtype:trojan-activity; sid:2008361; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Accessing)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008361

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008363
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ISMYIE)"; flow:to_server,established; content:"ISMYIE"; http_user_agent; depth:6; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008363; classtype:trojan-activity; sid:2008363; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (ISMYIE)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008363

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008391
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (svchost)"; flow:established,to_server; content:"svchost"; http_user_agent; depth:7; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008391; classtype:trojan-activity; sid:2008391; rev:13; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (svchost)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008391

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 13

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008400
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ReadFileURL)"; flow:established,to_server; content:"ReadFileURL"; http_user_agent; depth:11; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008400; classtype:trojan-activity; sid:2008400; rev:12; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (ReadFileURL)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008400

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 12

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008413
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (PcPcUpdater)"; flow:established,to_server; content:"PcPcUpdater"; http_user_agent; depth:11; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008413; classtype:trojan-activity; sid:2008413; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (PcPcUpdater)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008413

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008422
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Inet_read)"; flow:established,to_server; content:"Inet_read"; http_user_agent; depth:9; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008422; classtype:trojan-activity; sid:2008422; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Inet_read)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008422

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008423
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (CFS Agent)"; flow:established,to_server; content:"CFS Agent"; http_user_agent; depth:9; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008423; classtype:trojan-activity; sid:2008423; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (CFS Agent)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008423

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008424
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (CFS_DOWNLOAD)"; flow:established,to_server; content:"CFS_DOWNLOAD"; http_user_agent; depth:12; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008424; classtype:trojan-activity; sid:2008424; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (CFS_DOWNLOAD)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008424

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008427
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (AdiseExplorer)"; flow:established,to_server; content:"AdiseExplorer"; http_user_agent; depth:13; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008427; classtype:trojan-activity; sid:2008427; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (AdiseExplorer)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008427

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008428
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HTTP Downloader)"; flow: established,to_server; content:"HTTP Downloader"; http_user_agent; depth:15; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008428; classtype:trojan-activity; sid:2008428; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (HTTP Downloader)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008428

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008429
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HttpDownload)"; flow:established,to_server; content:"HttpDownload"; http_user_agent; depth:12; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008429; classtype:trojan-activity; sid:2008429; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (HttpDownload)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008429

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008440
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Download App)"; flow:established,to_server; content:"Download App"; http_user_agent; depth:12; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008440; classtype:trojan-activity; sid:2008440; rev:13; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Download App)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008440

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 13

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008458
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Downloader User-Agent (AutoDL\/1.0)"; flow:established,to_server; content:"GET"; nocase; http_method; content:"AutoDL/1.0"; http_user_agent; depth:10; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008458; classtype:trojan-activity; sid:2008458; rev:10; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Downloader User-Agent (AutoDL\/1.0)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008458

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008460
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (hacker)"; flow:established,to_server; content:"hacker"; http_user_agent; depth:6; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008460; classtype:trojan-activity; sid:2008460; rev:12; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (hacker)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008460

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 12

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008463
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ieguideupdate)"; flow:established,to_server; content:"ieguideupdate"; http_user_agent; depth:13; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008463; classtype:trojan-activity; sid:2008463; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (ieguideupdate)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008463

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008464
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (adsntD)"; flow:established,to_server; content:"adsntD"; http_user_agent; depth:6; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008464; classtype:trojan-activity; sid:2008464; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (adsntD)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008464

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008488
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (NULL)"; flow:established,to_server; content:"NULL"; http_user_agent; depth:4; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/bin/view/Main/2008488; classtype:trojan-activity; sid:2008488; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (NULL)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008488

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008494
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (ieagent)"; flow:established,to_server; content:"ieagent"; http_user_agent; depth:7; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008494; classtype:trojan-activity; sid:2008494; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (ieagent)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008494

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008495
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (antispyprogram)"; flow:established,to_server; content:"antispyprogram"; http_user_agent; depth:14; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008495; classtype:trojan-activity; sid:2008495; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (antispyprogram)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008495

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008504
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (SUiCiDE/1.5)"; flow:established,to_server; content:"SUiCiDE"; http_user_agent; depth:7; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/bin/view/Main/2008504; classtype:trojan-activity; sid:2008504; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (SUiCiDE/1.5)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008504

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008512
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (C slash)"; flow:established,to_server; content:"C|3a 5c|"; http_user_agent; depth:3; fast_pattern; content:!"|5c|Citrix|5c|"; http_header; content:!"|5c|Panda S"; nocase; http_header; content:!"|5c|Mapinfo"; http_header; nocase; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category USER_AGENTS; classtype:trojan-activity; sid:2008512; rev:18; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (C slash)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 18

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008513
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (msIE 7.0)"; flow:established,to_server; content:"msIE"; http_user_agent; depth:4; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008513; classtype:trojan-activity; sid:2008513; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (msIE 7.0)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008513

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008514
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (AVP2006IE)"; flow:established,to_server; content:"AVP200"; http_user_agent; depth:6; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008514; classtype:trojan-activity; sid:2008514; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (AVP2006IE)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008514

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008544
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (winlogon)"; flow:established,to_server; content:"winlogon"; http_user_agent; depth:8; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008544; classtype:trojan-activity; sid:2008544; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (winlogon)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008544

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008564
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Internet HTTP Request)"; flow:established,to_server; content:"Internet HTTP"; http_user_agent; depth:13; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008564; classtype:trojan-activity; sid:2008564; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Internet HTTP Request)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008564

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008643
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (Downloader1.2)"; flow:established,to_server; content:"Downloader"; http_user_agent; depth:10; pcre:"/User-Agent\: Downloader\d+\.\d/H"; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008643; classtype:trojan-activity; sid:2008643; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Detected (Downloader1.2)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008643

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008657
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (Compatible)"; flow:established,to_server; content:"Compatible"; http_user_agent; depth:10; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008657; classtype:trojan-activity; sid:2008657; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Detected (Compatible)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008657

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008658
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (GetUrlSize)"; flow:established,to_server; content:"GetUrlSize"; http_user_agent; depth:10; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008658; classtype:trojan-activity; sid:2008658; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Detected (GetUrlSize)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008658

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008663
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (aguarovex-loader v3.221)"; flow:established,to_server; content:"aguarovex-loader v"; http_user_agent; depth:18; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008663; classtype:trojan-activity; sid:2008663; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Detected (aguarovex-loader v3.221)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008663

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008734
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Detected (WINS_HTTP_SEND Program/1.0)"; flow:established,to_server; content:"WINS_HTTP_SEND"; http_user_agent; depth:14; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008734; classtype:trojan-activity; sid:2008734; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent Detected (WINS_HTTP_SEND Program/1.0)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008734

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008749
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (checkonline)"; flow:established,to_server; content:"checkonline"; http_user_agent; depth:11; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008749; classtype:trojan-activity; sid:2008749; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (checkonline)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008749

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008756
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Kvadrlson 1.0)"; flow:established,to_server; content:"Kvadrlson "; http_user_agent; depth:10; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008756; classtype:trojan-activity; sid:2008756; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Kvadrlson 1.0)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008756

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008767
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Kangkio User-Agent (lsosss)"; flow:established,to_server; content:"lsosss"; http_user_agent; depth:6; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2008767; classtype:trojan-activity; sid:2008767; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Kangkio User-Agent (lsosss)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2008767

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 6

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008797
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (miip)"; flow:established,to_server; content:"miip"; http_user_agent; depth:4; isdataat:!1,relative; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008797; classtype:trojan-activity; sid:2008797; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (miip)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008797

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008847
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Mozil1a)"; flow:established,to_server; content:"Mozil1a"; http_user_agent; depth:7; threshold:type limit,count 2,track by_src,seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008847; classtype:trojan-activity; sid:2008847; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Mozil1a)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008847

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008912
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Errordigger.com related)"; flow:established,to_server; content:"min"; http_user_agent; depth:3; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008912; classtype:trojan-activity; sid:2008912; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Errordigger.com related)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008912

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008913
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Trojan.Hijack.IrcBot.457 related)"; flow:established,to_server; content:"Mozilla/1.0 (compatible|3b 20|MSIE 8.0|3b|"; http_user_agent; depth:34; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/bin/view/Main/2008913; classtype:trojan-activity; sid:2008913; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Trojan.Hijack.IrcBot.457 related)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008913

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008914
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (xr - Worm.Win32.VB.cj related)"; flow:established,to_server; content:"xr"; http_user_agent; depth:2; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/bin/view/Main/2008914; classtype:trojan-activity; sid:2008914; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (xr - Worm.Win32.VB.cj related)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008914

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008916
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Yandesk)"; flow:established,to_server; content:"Yandesk"; http_user_agent; depth:7; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008916; classtype:trojan-activity; sid:2008916; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Yandesk)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008916

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008919
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent pricers.info related (section)"; flow:established,to_server; content:"sections"; http_user_agent; depth:8; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008919; classtype:trojan-activity; sid:2008919; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent pricers.info related (section)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008919

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008941
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (HELLO)"; flow:established,to_server; content:"HELLO"; http_user_agent; depth:5; isdataat:!1,relative; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008941; classtype:trojan-activity; sid:2008941; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (HELLO)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008941

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 11

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008956
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (IE/1.0)"; flow:to_server,established; content:"IE/1.0"; http_user_agent; depth:6; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/bin/view/Main/2008956; classtype:trojan-activity; sid:2008956; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (IE/1.0)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008956

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009355
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (runUpdater.html)"; flow:established,to_server; content:"runUpdater|2e|html"; http_user_agent; depth:15; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009355; classtype:trojan-activity; sid:2009355; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (runUpdater.html)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009355

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009356
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (runPatch.html)"; flow:established,to_server; content:"runPatch|2e|html"; http_user_agent; depth:13; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009356; classtype:trojan-activity; sid:2009356; rev:10; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (runPatch.html)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009356

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 10

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009534
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Poker)"; flow:to_server,established; content:"Poker"; http_user_agent; depth:5; isdataat:!1,relative; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,vil.nai.com/vil/content/v_130975.htm; reference:url,doc.emergingthreats.net/2009534; classtype:trojan-activity; sid:2009534; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (Poker)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,vil.nai.com/vil/content/v_130975.htm|url,doc.emergingthreats.net/2009534

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009541
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent filled with System Details - GET Request"; flow:established,to_server; content:"GET"; nocase; http_method; content:"mac="; http_user_agent; depth:4; nocase; content:"&hdid="; nocase; http_header; content:"&wlid="; nocase; content:"&start="; nocase; content:"&os="; nocase; content:"&mem="; nocase; content:"&alive"; nocase; content:"&ver="; nocase; content:"&mode="; nocase; content:"&guid"; content:"&install="; nocase; content:"&auto="; nocase; content:"&serveid"; nocase; content:"&area="; nocase; depth:400; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/2009541; classtype:trojan-activity; sid:2009541; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2020_02_24;)
` 

Name : **Suspicious User-Agent filled with System Details - GET Request** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009541

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-24

Rev version : 8

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009544
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (InHold) - Possible Trojan Downloader GET Request"; flow:established,to_server; content:"InHold"; http_user_agent; depth:6; isdataat:!1,relative; nocase; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009544; classtype:trojan-activity; sid:2009544; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, tag Trojan_Downloader, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (InHold) - Possible Trojan Downloader GET Request** 

Attack target : Client_Endpoint

Description : A Trojan-Downloader is a type of malware that is responsible for loading and facilitating the continued proliferation of further payloads upon the victim machine. Typically, Trojan-Downloaders will ensure further infection is successful but reporting a successful install, modifying system settings to ensure future malware can be installed/executed without issue, and enable persistency mechanisms for long term infection. Windows is the most commonly observed platform for this type of infection, however, it is not limited-- Macintosh OS X and Linux are also potential targets for compromise.
Valid Trojan-Downloader activity can include network connectivity to a command and control server to report successful infection on a victim machine. Typically, machines impacted with a Trojan-Downloader will have several system settings modified, such as modifications to the Registry where malicious entries may be made. Additionally, the download of a second-stage payload may occur once the original malware has ran. Trojan-Downloaders have been observed with the ability to exfiltrate sensitive data. Confirmation of hostile IP addresses or domains observed with Trojan-Downloader activity may take place in the ET Intelligence portal.
From a network perspective, malware that falls under the Trojan-Downloader has been observed performing activity that would trigger several Emerging Threats INFO, POLICY, and TROJAN style alerts, such as checking an external IP address, the presence of a downloaded executable, or a suspicious HTTP POST to a server. This combination of Trojan-Downloader alerts, as well as complimentary INFO, POLICY, or TROJAN alerts, would warrant an immediate follow up for a compromised workstation.

Tags : Trojan_Downloader, User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009544

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009703
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (INet)"; flow:established,to_server; content:"INet"; http_user_agent; depth:4; isdataat:!1,relative; threshold: type limit, count 2, track by_src, seconds 300; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009703; classtype:trojan-activity; sid:2009703; rev:9; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (INet)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009703

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009994
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-Agent (STEROID Download)"; flow:established,to_server; content:"STEROID Download"; nocase; http_user_agent; depth:16; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,anubis.iseclab.org/?action=result&task_id=17b118a86edba30f4f588db66eaf55d10; reference:url,security.thejoshmeister.com/2009/09/new-malware-ddos-botexe-etc-and.html; reference:url,doc.emergingthreats.net/2009994; classtype:trojan-activity; sid:2009994; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **User-Agent (STEROID Download)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,anubis.iseclab.org/?action=result&task_id=17b118a86edba30f4f588db66eaf55d10|url,security.thejoshmeister.com/2009/09/new-malware-ddos-botexe-etc-and.html|url,doc.emergingthreats.net/2009994

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010261
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS WindowsEnterpriseSuite FakeAV User-Agent TALWinHttpClient"; flow:established,to_server; content:"Mozilla/3.0(compatible|3b 20|TALWinHttpClient)"; http_user_agent; depth:41; isdataat:!1,relative; fast_pattern:21,19; metadata: former_category TROJAN; reference:url,www.threatexpert.com/report.aspx?md5=d9bcb4e4d650a6ed4402fab8f9ef1387; reference:url,doc.emergingthreats.net/2010261; classtype:trojan-activity; sid:2010261; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **WindowsEnterpriseSuite FakeAV User-Agent TALWinHttpClient** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.threatexpert.com/report.aspx?md5=d9bcb4e4d650a6ed4402fab8f9ef1387|url,doc.emergingthreats.net/2010261

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010678
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Win32.OnLineGames User-Agent (BigFoot)"; flow:to_server,established; content:"BigFoot"; nocase; http_user_agent; depth:7; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2010678; classtype:trojan-activity; sid:2010678; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Win32.OnLineGames User-Agent (BigFoot)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2010678

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011188
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Nine Ball User-Agent Detected (NQX315)"; flow:established,to_server; content:"NQX315"; http_user_agent; depth:6; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2011188; classtype:trojan-activity; sid:2011188; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Nine Ball User-Agent Detected (NQX315)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2011188

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013455
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (GUIDTracker)"; flow:to_server,established; content:"GUIDTracker"; http_user_agent; depth:11; metadata: former_category TROJAN; reference:url,threatexpert.com/report.aspx?md5=7a8807f4de0999dba66a8749b2366def; classtype:trojan-activity; sid:2013455; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_08_24, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (GUIDTracker)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,threatexpert.com/report.aspx?md5=7a8807f4de0999dba66a8749b2366def

CVE reference : Not defined

Creation date : 2011-08-24

Last modified date : 2019-10-11

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013561
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (windsoft)"; flow:established,to_server; content:"WindSoft"; http_user_agent; depth:8; isdataat:!1,relative; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013561; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_09_12, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (windsoft)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-12

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013881
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (NateFinder)"; flow:to_server,established; content:"NateFinder"; http_user_agent; depth:10; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013881; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_11_08, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (NateFinder)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013883
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (webfile)"; flow:to_server,established; content:"webfile"; http_user_agent; depth:7; metadata: former_category TROJAN; reference:url,threatexpert.com/reports.aspx?find=upsh.playmusic.co.kr; classtype:trojan-activity; sid:2013883; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_11_08, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (webfile)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,threatexpert.com/reports.aspx?find=upsh.playmusic.co.kr

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013884
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (DARecover)"; flow:to_server,established; content:"DARecover"; http_user_agent; depth:9; metadata: former_category TROJAN; reference:url,threatexpert.com/reports.aspx?find=clients.mydealassistant.com; classtype:trojan-activity; sid:2013884; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_11_08, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent (DARecover)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,threatexpert.com/reports.aspx?find=clients.mydealassistant.com

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007942
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (_)"; flow:to_server,established; content:"_"; http_user_agent; depth:1; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:url,doc.emergingthreats.net/bin/view/Main/2007942; classtype:trojan-activity; sid:2007942; rev:9; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Suspicious User Agent (_)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007942

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 9

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007833
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Eldorado.BHO User-Agent Detected (MSIE 5.5)"; flow:established,to_server; content:"GET"; nocase; http_method; content:"MSIE 5.5"; http_user_agent; depth:8; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007833; classtype:trojan-activity; sid:2007833; rev:8; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Eldorado.BHO User-Agent Detected (MSIE 5.5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007833

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 8

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011282
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (ScrapeBox)"; flow:to_server,established; content:"ScrapeBox"; depth:9; http_user_agent; metadata: former_category HUNTING; classtype:trojan-activity; sid:2011282; rev:5; metadata:created_at 2010_09_28, updated_at 2019_10_11;)
` 

Name : **Suspicious User Agent (ScrapeBox)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012295
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS suspicious user-agent (REKOM)"; flow:established,to_server; content:"GET"; http_method; content:"REKOM"; nocase; depth:5; http_user_agent; classtype:trojan-activity; sid:2012295; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_02_06, updated_at 2019_10_11;)
` 

Name : **suspicious user-agent (REKOM)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-06

Last modified date : 2019-10-11

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012386
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent VCTestClient"; flow:to_server,established; content:"VCTestClient"; depth:12; nocase; http_user_agent; classtype:trojan-activity; sid:2012386; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_02_27, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent VCTestClient** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-27

Last modified date : 2019-10-11

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012387
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent PrivacyInfoUpdate"; flow:to_server,established; content:"PrivacyInfoUpdate"; depth:17; nocase; http_user_agent; classtype:trojan-activity; sid:2012387; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_02_27, updated_at 2019_10_11;)
` 

Name : **Suspicious User-Agent PrivacyInfoUpdate** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-27

Last modified date : 2019-10-11

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012611
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent Sample"; flow:established,to_server; content:"sample"; nocase; http_user_agent; depth:6; classtype:trojan-activity; sid:2012611; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_03_31, updated_at 2020_04_19;)
` 

Name : **Suspicious User-Agent Sample** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2020-04-19

Rev version : 6

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012751
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS suspicious user agent string (changhuatong)"; flow:to_server,established; content:"changhuatong"; http_user_agent; depth:12; classtype:trojan-activity; sid:2012751; rev:3; metadata:created_at 2011_04_29, updated_at 2020_04_20;)
` 

Name : **suspicious user agent string (changhuatong)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-29

Last modified date : 2020-04-20

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012757
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS suspicious user agent string (CholTBAgent)"; flow:to_server,established; content:"CholTBAgent"; http_user_agent; depth:11; threshold: type limit, count 2, seconds 40, track by_src; classtype:trojan-activity; sid:2012757; rev:6; metadata:created_at 2011_04_29, updated_at 2020_04_20;)
` 

Name : **suspicious user agent string (CholTBAgent)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-29

Last modified date : 2020-04-20

Rev version : 6

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013542
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Win32/OnLineGames User-Agent (Revolution Win32)"; flow:established,to_server; content:"Revolution"; http_user_agent; depth:10; reference:url,threatexpert.com/report.aspx?md5=1431f4ab4bbe3ad1087eb14cf4d7dff9; classtype:trojan-activity; sid:2013542; rev:3; metadata:created_at 2011_09_06, updated_at 2020_04_20;)
` 

Name : **Win32/OnLineGames User-Agent (Revolution Win32)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,threatexpert.com/report.aspx?md5=1431f4ab4bbe3ad1087eb14cf4d7dff9

CVE reference : Not defined

Creation date : 2011-09-06

Last modified date : 2020-04-20

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013173
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET USER_AGENTS Atomic_Email_Hunter User-Agent Inbound"; flow:established,to_server; content:"Atomic_Email_Hunter/"; fast_pattern; http_user_agent; depth:20; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013173; rev:4; metadata:created_at 2011_07_04, updated_at 2019_10_15;)
` 

Name : **Atomic_Email_Hunter User-Agent Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-07-04

Last modified date : 2019-10-15

Rev version : 4

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013174
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Atomic_Email_Hunter User-Agent Outbound"; flow:established,to_server; content:"Atomic_Email_Hunter/"; fast_pattern; http_user_agent; depth:20; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013174; rev:4; metadata:created_at 2011_07_04, updated_at 2019_10_15;)
` 

Name : **Atomic_Email_Hunter User-Agent Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-07-04

Last modified date : 2019-10-15

Rev version : 4

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012860
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent SimpleClient 1.0"; flow:established,to_server; content:"SimpleClient "; http_user_agent; depth:13; reference:url,www.fortiguard.com/encyclopedia/virus/symbos_sagasi.a!tr.html; classtype:bad-unknown; sid:2012860; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_05_25, updated_at 2019_10_15;)
` 

Name : **Suspicious User-Agent SimpleClient 1.0** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : bad-unknown

URL reference : url,www.fortiguard.com/encyclopedia/virus/symbos_sagasi.a!tr.html

CVE reference : Not defined

Creation date : 2011-05-25

Last modified date : 2019-10-15

Rev version : 5

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013967
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (adlib)"; flow:established,to_server; content:"adlib/"; http_user_agent; depth:6; reference:url,blog.trendmicro.com/connections-between-droiddreamlight-and-droidkungfu/; classtype:trojan-activity; sid:2013967; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_11_23, updated_at 2019_10_15;)
` 

Name : **Suspicious User-Agent (adlib)** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,blog.trendmicro.com/connections-between-droiddreamlight-and-droidkungfu/

CVE reference : Not defined

Creation date : 2011-11-23

Last modified date : 2019-10-15

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028651
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Steam HTTP Client User-Agent"; flow:established,to_server; content:"Valve/Steam HTTP Client"; http_user_agent; depth:23; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category USER_AGENTS; classtype:policy-violation; sid:2028651; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_10_07, updated_at 2019_10_16;)
` 

Name : **Steam HTTP Client User-Agent** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-10-07

Last modified date : 2019-10-16

Rev version : 3

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027389
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Microsoft Dr Watson User-Agent (MSDW)"; flow:established,to_server; content:"MSDW"; depth:4; isdataat:!1,relative; http_user_agent; fast_pattern; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category USER_AGENTS; classtype:unknown; sid:2027389; rev:3; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_05_28, performance_impact Low, updated_at 2019_10_16;)
` 

Name : **Microsoft Dr Watson User-Agent (MSDW)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Web_Browsers

Alert Classtype : unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-28

Last modified date : 2019-10-16

Rev version : 3

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2028834
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (IExplorer 34)"; flow:established,to_server; content:"IExplorer 34"; http_user_agent; depth:12; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2028834; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_10_16, performance_impact Low, updated_at 2019_10_16;)
` 

Name : **Observed Suspicious UA (IExplorer 34)** 

Attack target : Client_Endpoint

Description : This will alert on a non-standard User-Agent which might be indicative of unwanted or malicious activity.

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-10-16

Last modified date : 2019-10-16

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2028842
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (reqwest/)"; flow:established,to_server; content:"reqwest/"; http_user_agent; depth:8; metadata: former_category USER_AGENTS; reference:md5,be59ae5fab354d29e53f11a08d805db7; classtype:bad-unknown; sid:2028842; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_10_16, performance_impact Low, updated_at 2019_10_16;)
` 

Name : **Suspicious User Agent (reqwest/)** 

Attack target : Client_Endpoint

Description : Signature triggers on unusual User-Agent header value.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,be59ae5fab354d29e53f11a08d805db7

CVE reference : Not defined

Creation date : 2019-10-16

Last modified date : 2019-10-16

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2028879
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Windows)"; flow:established,to_server; content:"Windows"; http_user_agent; depth:7; isdataat:!1,relative; metadata: former_category HUNTING; classtype:bad-unknown; sid:2028879; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_10_21, performance_impact Low, updated_at 2019_10_21;)
` 

Name : **Observed Suspicious UA (Windows)** 

Attack target : Client_Endpoint

Description : This will alert on a suspicious User-Agent which has been observed in malware traffic.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-10-21

Last modified date : 2019-10-21

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2021060
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS MSF Meterpreter Default User Agent"; flow:established,to_server; content:"Mozilla/4.0 (compatible|3b 20|MSIE 6.1|3b 20|Windows NT|29|"; http_user_agent; fast_pattern; depth:46; isdataat:!1,relative; reference:url,blog.didierstevens.com/2015/03/16/quickpost-metasploit-user-agent-strings; classtype:bad-unknown; sid:2021060; rev:3; metadata:created_at 2015_05_05, updated_at 2019_10_22;)
` 

Name : **MSF Meterpreter Default User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blog.didierstevens.com/2015/03/16/quickpost-metasploit-user-agent-strings

CVE reference : Not defined

Creation date : 2015-05-05

Last modified date : 2019-10-22

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028650
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Steam HTTP Client User-Agent"; flow:established,to_server; content:"SteamHTTPClient"; http_user_agent; depth:15; isdataat:!1,relative; threshold: type limit, track by_src, count 1, seconds 300; metadata: former_category USER_AGENTS; classtype:policy-violation; sid:2028650; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_10_07, updated_at 2019_10_22;)
` 

Name : **Steam HTTP Client User-Agent** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-10-07

Last modified date : 2019-10-22

Rev version : 3

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022775
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET USER_AGENTS BLEXBot User-Agent"; flow:established,to_server; content:"Mozilla/5.0 (compatible|3b 20|BLEXBot/"; fast_pattern; http_user_agent; depth:33; threshold:type limit, track by_dst, count 1, seconds 300; metadata: former_category MALWARE; reference:url,webmeup.com/about.html; classtype:misc-activity; sid:2022775; rev:3; metadata:created_at 2016_05_02, updated_at 2019_10_23;)
` 

Name : **BLEXBot User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,webmeup.com/about.html

CVE reference : Not defined

Creation date : 2016-05-02

Last modified date : 2019-10-23

Rev version : 3

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2007778
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS User-agent DownloadNetFile Win32.small.hsh downloader"; flow:established,to_server; content:"GET"; nocase; http_method; content:"DownloadNetFile"; http_user_agent; nocase; depth:15; isdataat:!1,relative; metadata: former_category TROJAN; reference:url,doc.emergingthreats.net/2007778; classtype:trojan-activity; sid:2007778; rev:15; metadata:created_at 2010_07_30, updated_at 2019_10_24;)
` 

Name : **User-agent DownloadNetFile Win32.small.hsh downloader** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007778

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-24

Rev version : 15

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013395
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent _updater_agent"; flow:established,to_server; content:"_updater_agent"; http_user_agent; depth:14; metadata: former_category TROJAN; classtype:trojan-activity; sid:2013395; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag User_Agent, signature_severity Major, created_at 2011_08_10, updated_at 2019_10_24;)
` 

Name : **Suspicious User-Agent _updater_agent** 

Attack target : Client_Endpoint

Description : Trojan User-Agent signatures are a class of alerts that specifically look for known Trojan User-Agent strings that are leveraged by compromised machines.  As part of HTTP, the web client must identify what software it is running by leveraging the user agent string.  Malware often specifies it’s own user agent string using either explicit user agent names, or more subtly tries to disguise itself as legitimate software by using strings that look like standard software like Internet Explorer, Mozilla, Chrome &c.  Malware authors often use a unique user agent string to help differentiate compromised clients from legitimate web traffic.  The Trojan often leverages this traffic is used to fetch additional payloads, configurations, and instructions--or to report back to command and control infrastructure.  

When reviewing a Trojan User Agent signature to determine if it is a legitimate hit, it is worth reviewing the IDS logs to determine if other alerts for related malware have triggered on this given client, as well as reviewing ET Intelligence to determine if the client is speaking to known malware infrastructure such as command and control systems.  If possible, reviewing a packet capture of the offending traffic can be helpful to identify if this is a legitimate hit or if there is a potential false positive due to obscure user agent headers.

Tags : User_Agent

Affected products : Any

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-10

Last modified date : 2019-10-24

Rev version : 4

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028912
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Client)"; flow:established,to_server; content:"Client"; http_user_agent; depth:6; isdataat:!1,relative; content:"User-Agent|3a 20|Client|0d 0a|"; fast_pattern; http_header; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2028912; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_10_28, updated_at 2019_10_28;)
` 

Name : **Observed Suspicious UA (Client)** 

Attack target : Client_Endpoint

Description : This will alert on a suspicious non-standard User-Agent observed in traffic.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-10-28

Last modified date : 2019-10-28

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028947
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (Random String)"; flow:established,to_server; content:"Random String"; http_user_agent; depth:13; isdataat:!1,relative; metadata: former_category HUNTING; reference:md5,a1e56bd465d1c1b5fc19384a3a7ec461; classtype:bad-unknown; sid:2028947; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_11_07, performance_impact Low, updated_at 2019_11_07;)
` 

Name : **Suspicious User-Agent (Random String)** 

Attack target : Client_Endpoint

Description : Signature triggers on a suspicious user-agent of "Random String"

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : md5,a1e56bd465d1c1b5fc19384a3a7ec461

CVE reference : Not defined

Creation date : 2019-11-07

Last modified date : 2019-11-07

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2028983
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (system_file/2.0)"; flow:established,to_server; content:"system_file/2.0"; http_user_agent; depth:15; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2028983; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_11_15, updated_at 2019_11_15;)
` 

Name : **Observed Suspicious UA (system_file/2.0)** 

Attack target : Client_Endpoint

Description : This will alert on a User-Agent observed in Mirai based exploit traffic.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-11-15

Last modified date : 2019-11-15

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029232
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (DxD)"; flow:established,to_server; content:"DxD"; http_user_agent; fast_pattern; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029232; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2020_01_06, performance_impact Low, updated_at 2020_01_06;)
` 

Name : **Observed Suspicious UA (DxD)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-01-06

Last modified date : 2020-01-06

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2029423
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS ABBCCoin Activity Observed"; flow:established,to_server; content:"User-Agent|3a 20|ABBCCoin"; fast_pattern; http_header; reference:md5,77ec579347955cfa32f219386337f5bb; classtype:misc-activity; sid:2029423; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2020_02_12, updated_at 2020_02_12;)
` 

Name : **ABBCCoin Activity Observed** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : md5,77ec579347955cfa32f219386337f5bb

CVE reference : Not defined

Creation date : 2020-02-12

Last modified date : 2020-02-12

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029544
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (VB OpenUrl)"; flow:to_server,established; content:"VB OpenUrl"; http_user_agent; depth:10; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029544; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_02_27, updated_at 2020_02_27;)
` 

Name : **Suspicious User-Agent (VB OpenUrl)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-02-27

Last modified date : 2020-02-27

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029554
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (\xa4)"; flow:established,to_server; content:"|0d 0a|User-Agent|3a 20 a4 0d 0a|"; fast_pattern; http_header; content:"|a4|"; http_user_agent; depth:1; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029554; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2020_03_02, updated_at 2020_03_02;)
` 

Name : **Observed Suspicious UA (\xa4)** 

Attack target : Client_Endpoint

Description : This will alert on a suspicious User-Agent content sometimes observed in hostile or unwanted traffic.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-02

Last modified date : 2020-03-02

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029569
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (easyhttp client)"; flow:established,to_server; content:"easyhttp client"; http_user_agent; depth:15; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029569; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_04, updated_at 2020_03_04;)
` 

Name : **Observed Suspicious UA (easyhttp client)** 

Attack target : Client_Endpoint

Description : This will alert on a non-standard User-Agent which may be used by nefarious or unwanted programs.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-04

Last modified date : 2020-03-04

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029749
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (explorersvc)"; flow:established,to_server; content:"explorersvc"; http_user_agent; depth:11; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029749; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_27, updated_at 2020_03_27;)
` 

Name : **Suspicious User Agent (explorersvc)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-27

Last modified date : 2020-03-27

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029750
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User Agent (KtulhuBrowser)"; flow:established,to_server; content:"KtulhuBrowser"; http_user_agent; depth:13; isdataat:!1,relative; nocase; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029750; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_27, updated_at 2020_03_27;)
` 

Name : **Suspicious User Agent (KtulhuBrowser)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-27

Last modified date : 2020-03-27

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029748
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (xPCAP)"; flow:established,to_server; content:"xPCAP"; http_user_agent; depth:5; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029748; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_27, updated_at 2020_03_27;)
` 

Name : **Observed Suspicious UA (xPCAP)** 

Attack target : Client_Endpoint

Description : This will alert on a non-standard User-Agent which could be malicious or unwanted.

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-27

Last modified date : 2020-03-27

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029752
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (Http-connect)"; flow:established,to_server; content:"Http-connect"; http_user_agent; depth:12; isdataat:!1,relative; metadata: former_category USER_AGENTS; classtype:bad-unknown; sid:2029752; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_03_30, updated_at 2020_03_30;)
` 

Name : **Observed Suspicious UA (Http-connect)** 

Attack target : Client_Endpoint

Description : This will alert on a non-standard User-Agent sometimes observed in malicious or unwanted traffic.

Tags : Not defined

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-30

Last modified date : 2020-03-30

Rev version : 2

Category : USER_AGENTS

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029771
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Shadowcoin Cryptocurrency UA Observed"; flow:established,to_server; content:"User-Agent|3a 20|ShadowCoin"; http_header; fast_pattern; classtype:misc-activity; sid:2029771; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2020_03_31, updated_at 2020_03_31;)
` 

Name : **Shadowcoin Cryptocurrency UA Observed** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-31

Last modified date : 2020-03-31

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029772
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Willowcoin Cryptocurrency UA Observed"; flow:established,to_server; content:"User-Agent|3a 20|WillowCoin"; http_header; fast_pattern; classtype:misc-activity; sid:2029772; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2020_03_31, updated_at 2020_03_31;)
` 

Name : **Willowcoin Cryptocurrency UA Observed** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-03-31

Last modified date : 2020-03-31

Rev version : 2

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027762
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS AnyDesk Remote Desktop Software User-Agent"; flow:established,to_server; content:"AnyDesk"; http_user_agent; depth:7; metadata: former_category USER_AGENTS; reference:md5,1501639af59b0ff39d41577af30367cf; classtype:policy-violation; sid:2027762; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, performance_impact Low, updated_at 2020_04_10;)
` 

Name : **AnyDesk Remote Desktop Software User-Agent** 

Attack target : Client_Endpoint

Description : Signature triggers on AnyDesk Remote Desktop Software's User-Agent (AnyDesk) being observed on the network. 

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : md5,1501639af59b0ff39d41577af30367cf

CVE reference : Not defined

Creation date : 2019-07-26

Last modified date : 2020-04-10

Rev version : 3

Category : USER_AGENTS

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2029892
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Malicious CASPER/Mirai UA"; flow:established,to_server; content:"Mozilla/4.0   (compatible|3b|   MSIE   5.01|3b|   Windows   NT   5.0)"; depth:63; isdataat:!1,relative; fast_pattern; http_user_agent; reference:url,www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf; reference:md5,ea78869555018cdab3699e2df5d7e7f8; classtype:misc-activity; sid:2029892; rev:2; metadata:created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Observed Malicious CASPER/Mirai UA** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf|md5,ea78869555018cdab3699e2df5d7e7f8

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : USER_AGENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029980
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (PhoneMonitor)"; flow:established,to_server; content:"PhoneMonitor"; http_user_agent; depth:12; isdataat:!1,relative; metadata: former_category USER_AGENTS; reference:md5,09aa3bb05a55b0df864d1e1709c29960; reference:url,blog.trendmicro.com/trendlabs-security-intelligence/coronavirus-update-app-leads-to-project-spy-android-and-ios-spyware/; classtype:trojan-activity; sid:2029980; rev:2; metadata:attack_target Mobile_Client, signature_severity Major, created_at 2020_04_20, performance_impact Low, updated_at 2020_04_20;)
` 

Name : **Observed Suspicious UA (PhoneMonitor)** 

Attack target : Mobile_Client

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,09aa3bb05a55b0df864d1e1709c29960|url,blog.trendmicro.com/trendlabs-security-intelligence/coronavirus-update-app-leads-to-project-spy-android-and-ios-spyware/

CVE reference : Not defined

Creation date : 2020-04-20

Last modified date : 2020-04-20

Rev version : 2

Category : USER_AGENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

