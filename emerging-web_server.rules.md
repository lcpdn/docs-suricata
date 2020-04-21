# 2002365
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 3443 (msg:"ET WEB_SERVER HP OpenView Network Node Manager Remote Command Execution Attempt"; flow:to_server,established; content:"/OvCgi/connectedNodes.ovpl?"; nocase; pcre:"/node=.*\|.+\|/i"; reference:bugtraq,14662; reference:url,doc.emergingthreats.net/2002365; classtype:web-application-attack; sid:2002365; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HP OpenView Network Node Manager Remote Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14662|url,doc.emergingthreats.net/2002365

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000559
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 443 (msg:"ET WEB_SERVER THCIISLame IIS SSL Exploit Attempt"; flow: to_server,established; content:"THCOWNZIIS!"; reference:url,www.thc.org/exploits/THCIISSLame.c; reference:url,isc.sans.org/diary.php?date=2004-07-17; reference:url,doc.emergingthreats.net/2000559; classtype:web-application-attack; sid:2000559; rev:14; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **THCIISLame IIS SSL Exploit Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.thc.org/exploits/THCIISSLame.c|url,isc.sans.org/diary.php?date=2004-07-17|url,doc.emergingthreats.net/2000559

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002900
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER CGI AWstats Migrate Command Attempt"; flow:established,to_server; uricontent:"/awstats.pl?"; nocase; uricontent:"/migrate"; pcre:"/migrate\s*=\s*\|/Ui"; reference:bugtraq,17844; reference:url,doc.emergingthreats.net/2002900; classtype:web-application-attack; sid:2002900; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **CGI AWstats Migrate Command Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,17844|url,doc.emergingthreats.net/2002900

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002362
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Barracuda Spam Firewall img.pl Remote Command Execution Attempt"; flow: to_server,established; uricontent:"/cgi-bin/img.pl?"; nocase; pcre:"/(f=.+\|)/Ui"; reference:bugtraq,14712; reference:url,doc.emergingthreats.net/2002362; classtype:web-application-attack; sid:2002362; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Barracuda Spam Firewall img.pl Remote Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14712|url,doc.emergingthreats.net/2002362

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002685
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Barracuda Spam Firewall img.pl Remote Directory Traversal Attempt"; flow: to_server,established; uricontent:"/cgi-bin/img.pl?"; nocase; pcre:"/(f=\.\..+)/Ui"; reference:bugtraq,14710; reference:url,doc.emergingthreats.net/2002685; classtype:web-application-attack; sid:2002685; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Barracuda Spam Firewall img.pl Remote Directory Traversal Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14710|url,doc.emergingthreats.net/2002685

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003086
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Barracuda Spam Firewall preview_email.cgi Remote Command Execution"; flow: to_server,established; uricontent:"/cgi-bin/preview_email.cgi?"; nocase; pcre:"/file=.*\|/Ui"; reference:bugtraq,19276; reference:url,doc.emergingthreats.net/2003086; classtype:web-application-attack; sid:2003086; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Barracuda Spam Firewall preview_email.cgi Remote Command Execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,19276|url,doc.emergingthreats.net/2003086

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003087
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Barracuda Spam Firewall preview_email.cgi Remote Directory Traversal Attempt"; flow: to_server,established; uricontent:"/cgi-bin/preview_email.cgi?"; nocase; pcre:"/file=.+\.\..+\|/Ui"; reference:bugtraq,19276; reference:url,doc.emergingthreats.net/2003087; classtype:web-application-attack; sid:2003087; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Barracuda Spam Firewall preview_email.cgi Remote Directory Traversal Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,19276|url,doc.emergingthreats.net/2003087

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002721
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Cisco IOS HTTP set enable password attack"; flow:established,to_server; uricontent:"/configure/"; uricontent:"/enable/"; reference:cve,2005-3921; reference:bugtraq,15602; reference:url,www.infohacking.com/INFOHACKING_RESEARCH/Our_Advisories/cisco/index.html; reference:url,doc.emergingthreats.net/2002721; classtype:web-application-attack; sid:2002721; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Cisco IOS HTTP set enable password attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2005-3921|bugtraq,15602|url,www.infohacking.com/INFOHACKING_RESEARCH/Our_Advisories/cisco/index.html|url,doc.emergingthreats.net/2002721

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2004556
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Cisco CallManager XSS Attempt serverlist.asp pattern"; flow:established,to_server; uricontent:"/CCMAdmin/serverlist.asp?"; nocase; uricontent:"pattern="; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2832; reference:url,www.secunia.com/advisories/25377; reference:url,doc.emergingthreats.net/2004556; classtype:web-application-attack; sid:2004556; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Cisco CallManager XSS Attempt serverlist.asp pattern** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2832|url,www.secunia.com/advisories/25377|url,doc.emergingthreats.net/2004556

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009770
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible UNION SELECT SQL Injection In Cookie"; flow:to_server,established; content:"|0d 0a|Cookie|3A|"; nocase; content:"UNION%20"; within:200; nocase; content:"SELECT"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]+UNION.+SELECT/i"; reference:url,www.w3schools.com/sql/sql_union.asp; reference:url,www.w3schools.com/sql/sql_select.asp; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,doc.emergingthreats.net/2009770; classtype:web-application-attack; sid:2009770; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible UNION SELECT SQL Injection In Cookie** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.w3schools.com/sql/sql_union.asp|url,www.w3schools.com/sql/sql_select.asp|url,en.wikipedia.org/wiki/SQL_injection|url,www.owasp.org/index.php/SQL_Injection|url,doc.emergingthreats.net/2009770

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009771
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible SELECT FROM SQL Injection In Cookie"; flow:to_server,established; content:"|0d 0a|Cookie|3A|"; nocase; content:"SELECT%20"; within:200; nocase; content:"FROM"; nocase; distance:0; pcre:"/\x0d\x0aCookie\x3a[^\n]+SELECT.+FROM/i"; reference:url,www.w3schools.com/sql/sql_select.asp; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,doc.emergingthreats.net/2009771; classtype:web-application-attack; sid:2009771; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible SELECT FROM SQL Injection In Cookie** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.w3schools.com/sql/sql_select.asp|url,en.wikipedia.org/wiki/SQL_injection|url,www.owasp.org/index.php/SQL_Injection|url,doc.emergingthreats.net/2009771

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009772
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible DELETE FROM SQL Injection In Cookie"; flow:to_server,established; content:"|0d 0a|Cookie|3A|"; nocase; content:"DELETE%20"; within:200; nocase; content:"FROM"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]DELETE.+FROM/i"; reference:url,www.w3schools.com/Sql/sql_delete.asp; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,doc.emergingthreats.net/2009772; classtype:web-application-attack; sid:2009772; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible DELETE FROM SQL Injection In Cookie** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.w3schools.com/Sql/sql_delete.asp|url,en.wikipedia.org/wiki/SQL_injection|url,www.owasp.org/index.php/SQL_Injection|url,doc.emergingthreats.net/2009772

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009773
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible INSERT INTO SQL Injection In Cookie"; flow:to_server,established; content:"|0d 0a|Cookie|3A|"; nocase; content:"INSERT%20"; nocase; within:200; content:"INTO"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]INSERT.+INTO/i"; reference:url,www.w3schools.com/SQL/sql_insert.asp; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,doc.emergingthreats.net/2009773; classtype:web-application-attack; sid:2009773; rev:36; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible INSERT INTO SQL Injection In Cookie** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.w3schools.com/SQL/sql_insert.asp|url,en.wikipedia.org/wiki/SQL_injection|url,www.owasp.org/index.php/SQL_Injection|url,doc.emergingthreats.net/2009773

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 36

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010038
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible INTO OUTFILE Arbitrary File Write SQL Injection In Cookie"; flow:to_server,established; content:"|0d 0a|Cookie|3A|"; nocase; content:"INTO%20"; nocase; within:200; content:"OUTFILE"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]INTO.+OUTFILE/i"; reference:url,www.milw0rm.com/papers/372; reference:url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection; reference:url,websec.wordpress.com/2007/11/17/mysql-into-outfile/; reference:url,doc.emergingthreats.net/2010038; classtype:web-application-attack; sid:2010038; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible INTO OUTFILE Arbitrary File Write SQL Injection In Cookie** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.milw0rm.com/papers/372|url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection|url,websec.wordpress.com/2007/11/17/mysql-into-outfile/|url,doc.emergingthreats.net/2010038

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009484
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Cpanel lastvisit.html Arbitary file disclosure"; flow:to_server,established; content:"GET "; depth:4; uricontent:"lastvist.html?"; nocase; uricontent:"domain="; nocase; content:"../"; depth:200; reference:url,milw0rm.com/exploits/9039; reference:bugtraq,35518; reference:url,doc.emergingthreats.net/2009484; classtype:web-application-attack; sid:2009484; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Cpanel lastvisit.html Arbitary file disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9039|bugtraq,35518|url,doc.emergingthreats.net/2009484

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002376
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER IBM Lotus Domino BaseTarget XSS attempt"; flow:to_server,established; uricontent:"OpenForm"; nocase; pcre:"/BaseTarget=.*?\"/iU"; reference:bugtraq,14845; reference:url,doc.emergingthreats.net/2002376; classtype:web-application-attack; sid:2002376; rev:10; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **IBM Lotus Domino BaseTarget XSS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14845|url,doc.emergingthreats.net/2002376

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002377
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER IBM Lotus Domino Src XSS attempt"; flow:to_server,established; uricontent:"OpenFrameSet"; nocase; pcre:"/src=.*\"><\/FRAMESET>.*<script>.*<\/script>/iU"; reference:bugtraq,14846; reference:url,doc.emergingthreats.net/2002377; classtype:web-application-attack; sid:2002377; rev:9; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **IBM Lotus Domino Src XSS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14846|url,doc.emergingthreats.net/2002377

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010517
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)"; flow:from_server,established; content:"HTTP/1.1 404 Not Found|0d 0a|"; depth:24; nocase; content:"<script"; nocase; within:512; metadata: former_category WEB_SERVER; reference:url,doc.emergingthreats.net/2010517; classtype:web-application-attack; sid:2010517; rev:3; metadata:created_at 2010_07_30, updated_at 2017_09_08;)
` 

Name : **Possible HTTP 404 XSS Attempt (Local Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010517

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-09-08

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010970
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER HP OpenView Network Node Manager OvWebHelp.exe Heap Buffer Overflow Attempt"; flow:established,to_server; content:"POST "; depth:5; nocase; uricontent:"/OvCgi/OvWebHelp.exe"; nocase; content:"Topic="; nocase; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:cve,2009-4178; reference:url,doc.emergingthreats.net/2010970; classtype:web-application-attack; sid:2010970; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **HP OpenView Network Node Manager OvWebHelp.exe Heap Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2009-4178|url,doc.emergingthreats.net/2010970

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001343
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER IIS ASP.net Auth Bypass / Canonicalization % 5 C"; flow: to_server,established; uricontent:".aspx"; nocase; content:"GET"; nocase; depth: 3; content:"%5C"; depth: 200; nocase; content:"aspx"; within:100; reference:url,doc.emergingthreats.net/2001343; classtype:web-application-attack; sid:2001343; rev:22; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **IIS ASP.net Auth Bypass / Canonicalization % 5 C** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2001343

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 22

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002864
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER osCommerce extras/update.php disclosure"; flow:to_server,established; uricontent:"extras/update.php"; nocase; reference:url,retrogod.altervista.org/oscommerce_22_adv.html; reference:url,doc.emergingthreats.net/2002864; classtype:attempted-recon; sid:2002864; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **osCommerce extras/update.php disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,retrogod.altervista.org/oscommerce_22_adv.html|url,doc.emergingthreats.net/2002864

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002131
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Oracle Reports XML Information Disclosure"; flow:established,to_server; content:"GET "; depth:4; nocase; uricontent:"CUSTOMIZE=/"; nocase; pcre:"/(showenv|parsequery|rwservlet)\?.*CUSTOMIZE=\//Ui"; reference:url,www.oracle.com/technology/products/reports/index.html; reference:url,www.red-database-security.com/advisory/oracle_reports_read_any_xml_file.html; reference:url,doc.emergingthreats.net/2002131; classtype:web-application-activity; sid:2002131; rev:10; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Oracle Reports XML Information Disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.oracle.com/technology/products/reports/index.html|url,www.red-database-security.com/advisory/oracle_reports_read_any_xml_file.html|url,doc.emergingthreats.net/2002131

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002132
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER Oracle Reports DESFORMAT Information Disclosure"; flow:established,to_server; content:"GET "; depth:4; nocase; uricontent:"destype=file"; nocase; uricontent:"desformat="; nocase; pcre:"/(showenv|parsequery|rwservlet)\?.*destype=file.*desformat=\//Ui"; reference:url,www.oracle.com/technology/products/reports/index.html; reference:url,www.red-database-security.com/advisory/oracle_reports_read_any_file.html; reference:url,doc.emergingthreats.net/2002132; classtype:web-application-activity; sid:2002132; rev:10; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Oracle Reports DESFORMAT Information Disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.oracle.com/technology/products/reports/index.html|url,www.red-database-security.com/advisory/oracle_reports_read_any_file.html|url,doc.emergingthreats.net/2002132

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002133
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Oracle Reports OS Command Injection Attempt"; flow:established,to_server; content:"GET "; depth:4; nocase; uricontent:"report="; nocase; pcre:"/(showenv|parsequery|rwservlet)\?.*report=.*\.(rdf|rep)/Ui"; reference:url,www.oracle.com/technology/products/reports/index.html; reference:url,www.red-database-security.com/advisory/oracle_reports_run_any_os_command.html; reference:url,doc.emergingthreats.net/2002133; classtype:web-application-activity; sid:2002133; rev:10; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Oracle Reports OS Command Injection Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.oracle.com/technology/products/reports/index.html|url,www.red-database-security.com/advisory/oracle_reports_run_any_os_command.html|url,doc.emergingthreats.net/2002133

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009151
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER PHP Generic Remote File Include Attempt (HTTP)"; flow:to_server,established; uricontent:".php"; nocase; uricontent:"=http|3a|/"; nocase; pcre:"/\x2Ephp\x3F.{0,300}\x3Dhttp\x3A\x2F[^\x3F\x26]+\x3F/Ui"; reference:url,doc.emergingthreats.net/2009151; classtype:web-application-attack; sid:2009151; rev:8; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHP Generic Remote File Include Attempt (HTTP)** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009151

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010286
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER SELECT INSTR in Cookie, Possible ORACLE Related Blind SQL Injection Attempt"; flow:established,to_server; content:"|0d 0a|Cookie|3A|"; nocase; content:"SELECT%20"; nocase; within:200; content:"INSTR"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]SELECT.+INSTR/i"; reference:url,www.psoug.org/reference/substr_instr.html; reference:url,www.easywebtech.com/artical/Oracle_INSTR.html; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,msdn.microsoft.com/en-us/library/ms161953.aspx; reference:url,doc.emergingthreats.net/2010286; classtype:web-application-attack; sid:2010286; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SELECT INSTR in Cookie, Possible ORACLE Related Blind SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.psoug.org/reference/substr_instr.html|url,www.easywebtech.com/artical/Oracle_INSTR.html|url,www.owasp.org/index.php/SQL_Injection|url,msdn.microsoft.com/en-us/library/ms161953.aspx|url,doc.emergingthreats.net/2010286

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010287
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER SELECT SUBSTR/ING in Cookie, Possible Blind SQL Injection Attempt"; flow:established,to_server; content:"|0d 0a|Cookie|3A|"; nocase; content:"SELECT%20"; nocase; within:200; content:"SUBSTR"; nocase; distance:0; pcre:"/\x0a\x0dCookie\x3a[^\n]SELECT.+SUBSTR/i"; reference:url,www.1keydata.com/sql/sql-substring.html; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,msdn.microsoft.com/en-us/library/ms161953.aspx; reference:url,doc.emergingthreats.net/2010287; classtype:web-application-attack; sid:2010287; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SELECT SUBSTR/ING in Cookie, Possible Blind SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.1keydata.com/sql/sql-substring.html|url,www.owasp.org/index.php/SQL_Injection|url,msdn.microsoft.com/en-us/library/ms161953.aspx|url,doc.emergingthreats.net/2010287

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011040
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible Usage of MYSQL Comments in URI for SQL Injection"; flow:established,to_server; uricontent:"/*"; uricontent:"*/"; pcre:"/\x2F\x2A.+\x2A\x2F/U"; reference:url,dev.mysql.com/doc/refman/5.0/en/comments.html; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2011040; classtype:web-application-attack; sid:2011040; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Possible Usage of MYSQL Comments in URI for SQL Injection** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,dev.mysql.com/doc/refman/5.0/en/comments.html|url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2011040

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003903
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Microsoft SharePoint XSS Attempt default.aspx"; flow:established,to_server; uricontent:"/default.aspx?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2581; reference:url,www.securityfocus.com/bid/23832; reference:url,doc.emergingthreats.net/2003903; classtype:web-application-attack; sid:2003903; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Microsoft SharePoint XSS Attempt default.aspx** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2581|url,www.securityfocus.com/bid/23832|url,doc.emergingthreats.net/2003903

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003904
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Microsoft SharePoint XSS Attempt index.php form mail"; flow:established,to_server; uricontent:"/contact/contact/index.php?"; nocase; uricontent:"form[mail]="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2579; reference:url,www.securityfocus.com/bid/23834; reference:url,doc.emergingthreats.net/2003904; classtype:web-application-attack; sid:2003904; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Microsoft SharePoint XSS Attempt index.php form mail** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2579|url,www.securityfocus.com/bid/23834|url,doc.emergingthreats.net/2003904

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011015
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible Sun Microsystems Sun Java System Web Server Remote File Disclosure Attempt"; flow:established,to_server; content:"UNLOCK"; nocase; depth:6; content:"Connection|3A| Close"; nocase; distance:0; content:"Lock-token|3A|"; nocase; within:100; reference:url,www.packetstormsecurity.org/1004-exploits/sun-knockout.txt; reference:url,doc.emergingthreats.net/2011015; classtype:web-application-attack; sid:2011015; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Sun Microsystems Sun Java System Web Server Remote File Disclosure Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.packetstormsecurity.org/1004-exploits/sun-knockout.txt|url,doc.emergingthreats.net/2011015

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011016
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible Sun Microsystems Sun Java System Web Server Long OPTIONS URI Overflow Attmept"; flow:established,to_server; content:"OPTIONS|20|"; depth:8; nocase; isdataat:400,relative; content:!"|0A|"; within:400; reference:url,www.packetstormsecurity.com/1004-exploits/sunjavasystem-exec.txt; reference:cve,2010-0361; reference:url,doc.emergingthreats.net/2011016; classtype:web-application-attack; sid:2011016; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Sun Microsystems Sun Java System Web Server Long OPTIONS URI Overflow Attmept** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.packetstormsecurity.com/1004-exploits/sunjavasystem-exec.txt|cve,2010-0361|url,doc.emergingthreats.net/2011016

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003099
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Poison Null Byte"; flow:established,to_server; uricontent:"|00|"; depth:2400; reference:cve,2006-4542; reference:cve,2006-4458; reference:cve,2006-3602; reference:url,www.security-assessment.com/Whitepapers/0x00_vs_ASP_File_Uploads.pdf; reference:url,doc.emergingthreats.net/2003099; classtype:web-application-activity; sid:2003099; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Poison Null Byte** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : cve,2006-4542|cve,2006-4458|cve,2006-3602|url,www.security-assessment.com/Whitepapers/0x00_vs_ASP_File_Uploads.pdf|url,doc.emergingthreats.net/2003099

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002844
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER WebDAV search overflow"; flow:to_server,established; content:"SEARCH "; depth:8; nocase; isdataat:1000,relative; content:!"|0a|"; within:1000; reference:cve,2003-0109; reference:url,doc.emergingthreats.net/2002844; classtype:web-application-attack; sid:2002844; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **WebDAV search overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2003-0109|url,doc.emergingthreats.net/2002844

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011160
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Apache Axis2 xsd Parameter Directory Traversal Attempt"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/axis2/services/Version?"; nocase; uricontent:"xsd="; nocase; content:"../"; depth:200; reference:bugtraq,40343; reference:url,doc.emergingthreats.net/2011160; classtype:web-application-attack; sid:2011160; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Apache Axis2 xsd Parameter Directory Traversal Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,40343|url,doc.emergingthreats.net/2011160

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011291
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Asprox Spambot SQL-Injection Atempt"; flow:established,to_server; content:"GET"; http_method; content:"declare "; http_uri; nocase; content:"char("; http_uri; nocase; content:"exec(@"; nocase; http_uri; classtype:web-application-attack; sid:2011291; rev:3; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Asprox Spambot SQL-Injection Atempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012151
`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER PHP Large Subnormal Double Precision Floating Point Number PHP DoS Inbound"; flow:established,to_server; content:"2.2250738585072011e-308"; nocase; reference:url,bugs.php.net/bug.php?id=53632; classtype:attempted-dos; sid:2012151; rev:1; metadata:created_at 2011_01_06, updated_at 2011_01_06;)
` 

Name : **PHP Large Subnormal Double Precision Floating Point Number PHP DoS Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,bugs.php.net/bug.php?id=53632

CVE reference : Not defined

Creation date : 2011-01-06

Last modified date : 2011-01-06

Rev version : 1

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010687
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow Attempt"; flow:established,to_server; content:"GET "; depth:4; nocase; content:"/OvCgi/Main/Snmp.exe"; http_uri; nocase; content:"Host="; nocase; content:"Oid="; nocase; within:50; isdataat:600,relative; pcre:"/\x2FOvCgi\x2FMain\x2FSnmp\x2Eexe.+id\x3D.{600}/smi"; reference:cve,2009-3849; reference:url,doc.emergingthreats.net/2010687; classtype:web-application-attack; sid:2010687; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2009-3849|url,doc.emergingthreats.net/2010687

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101979
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER perl post attempt"; flow:to_server,established; content:"POST"; http_method; content:"/perl/"; http_uri; reference:bugtraq,5520; reference:cve,2002-1436; reference:nessus,11158; classtype:web-application-attack; sid:2101979; rev:6; metadata:created_at 2010_09_23, updated_at 2020_04_20;)
` 

Name : **perl post attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,5520|cve,2002-1436|nessus,11158

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2020-04-20

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012708
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER HTTP 414 Request URI Too Large"; flow:from_server,established; content:"HTTP/1.1 414 Request-URI Too Large"; depth:35; nocase; classtype:web-application-attack; sid:2012708; rev:2; metadata:created_at 2011_04_22, updated_at 2011_04_22;)
` 

Name : **HTTP 414 Request URI Too Large** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-22

Last modified date : 2011-04-22

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101945
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER unicode directory traversal attempt"; flow:to_server,established; content:"/..%255c.."; nocase; reference:bugtraq,1806; reference:cve,2000-0884; reference:nessus,10537; classtype:web-application-attack; sid:2101945; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unicode directory traversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,1806|cve,2000-0884|nessus,10537

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101852
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER robots.txt access"; flow:to_server,established; content:"/robots.txt"; http_uri; nocase; reference:nessus,10302; classtype:web-application-activity; sid:2101852; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **robots.txt access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,10302

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101857
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER robot.txt access"; flow:to_server,established; content:"/robot.txt"; http_uri; nocase; reference:nessus,10302; classtype:web-application-activity; sid:2101857; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **robot.txt access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,10302

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101809
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Apache Chunked-Encoding worm attempt"; flow:to_server,established; content:"CCCCCCC|3A| AAAAAAAAAAAAAAAAAAA"; nocase; reference:bugtraq,4474; reference:bugtraq,4485; reference:bugtraq,5033; reference:cve,2002-0071; reference:cve,2002-0079; reference:cve,2002-0392; classtype:web-application-attack; sid:2101809; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Apache Chunked-Encoding worm attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,4474|bugtraq,4485|bugtraq,5033|cve,2002-0071|cve,2002-0079|cve,2002-0392

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101817
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER MS Site Server default login attempt"; flow:to_server,established; content:"/SiteServer/Admin/knowledge/persmbr/"; nocase; http_uri; content:"TERBUF9Bbm9ueW1vdXM6TGRhcFBhc3N3b3JkXzE"; pcre:"/^Authorization|3A|\s*Basic\s+TERBUF9Bbm9ueW1vdXM6TGRhcFBhc3N3b3JkXzE=/smi"; reference:nessus,11018; classtype:web-application-attack; sid:2101817; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MS Site Server default login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : nessus,11018

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101818
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER MS Site Server admin attempt"; flow:to_server,established; content:"/Site Server/Admin/knowledge/persmbr/"; nocase; http_uri; reference:nessus,11018; classtype:web-application-attack; sid:2101818; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MS Site Server admin attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : nessus,11018

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101847
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER webalizer access"; flow:established,to_server; content:"/webalizer/"; nocase; http_uri; reference:bugtraq,3473; reference:cve,2001-0835; reference:nessus,10816; classtype:web-application-activity; sid:2101847; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **webalizer access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,3473|cve,2001-0835|nessus,10816

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101874
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Oracle Java Process Manager access"; flow:to_server,established; content:"/oprocmgr-status"; http_uri; reference:nessus,10851; classtype:web-application-activity; sid:2101874; rev:5; metadata:created_at 2010_09_23, updated_at 2020_04_20;)
` 

Name : **Oracle Java Process Manager access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,10851

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2020-04-20

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101738
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER global.inc access"; flow:to_server,established; content:"/global.inc"; nocase; http_uri; reference:bugtraq,4612; reference:cve,2002-0614; classtype:web-application-attack; sid:2101738; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **global.inc access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,4612|cve,2002-0614

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012926
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Apache APR apr_fnmatch Stack Overflow Denial of Service"; flow:to_server,established; urilen:>1400; content:"|2F 3F|P|3D 2A 3F 2A 3F 2A 3F 2A 3F 2A 3F|"; http_uri; pcre:"/(\x2a\x3f){700}/U"; reference:cve,2011-0419; reference:url,cxib.net/stuff/apr_fnmatch.txt; reference:url,bugzilla.redhat.com/show_bug.cgi?id=703390; classtype:attempted-dos; sid:2012926; rev:3; metadata:created_at 2011_06_02, updated_at 2020_04_20;)
` 

Name : **Apache APR apr_fnmatch Stack Overflow Denial of Service** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2011-0419|url,cxib.net/stuff/apr_fnmatch.txt|url,bugzilla.redhat.com/show_bug.cgi?id=703390

CVE reference : Not defined

Creation date : 2011-06-02

Last modified date : 2020-04-20

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101649
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER perl command attempt"; flow:to_server,established; content:"/perl?"; http_uri; nocase; reference:arachnids,219; reference:cve,1999-0509; reference:nessus,10173; reference:url,www.cert.org/advisories/CA-1996-11.html; classtype:attempted-recon; sid:2101649; rev:10; metadata:created_at 2010_09_23, updated_at 2020_04_20;)
` 

Name : **perl command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,219|cve,1999-0509|nessus,10173|url,www.cert.org/advisories/CA-1996-11.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2020-04-20

Rev version : 11

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013002
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible file Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=file|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013002; rev:5; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible file Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013001
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=php|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013001; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible php Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013000
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible ftps Local File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=ftps|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013000; rev:4; metadata:affected_product Web_Server_Applications, attack_target Server, deployment Datacenter, tag Local_File_Inclusion, signature_severity Major, created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible ftps Local File Inclusion Attempt** 

Attack target : Server

Description : Local File Inclusion (LFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. The vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. This vulnerability occurs when a web application receives a file path as input but this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected. PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP programming and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

This can lead to something as simple as outputting the contents of a file, but, depending on the severity, it can also lead to:
Code execution on the web server
Denial of Service (DoS)
Sensitive Information Disclosure

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch more sophisticated attacks if a server respond in a way that identifies it as vulnerable. You may see hundreds of these alerts in a short period of time. If you see a HTTP 200 response to a HTTP request that generated an alert, you’ll want to investigate further. Typically, evidence of a successful attack will show your configuration files (wp-config.php, configuration.php, /etc/passwd, etc...) being served to the attacker. 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Local_File_Inclusion

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012999
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible ftp Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=ftp|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2012999; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible ftp Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012998
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible https Local File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=https|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2012998; rev:4; metadata:affected_product Web_Server_Applications, attack_target Server, deployment Datacenter, tag Local_File_Inclusion, signature_severity Major, created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible https Local File Inclusion Attempt** 

Attack target : Server

Description : Local File Inclusion (LFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. The vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. This vulnerability occurs when a web application receives a file path as input but this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected. PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP programming and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

This can lead to something as simple as outputting the contents of a file, but, depending on the severity, it can also lead to:
Code execution on the web server
Denial of Service (DoS)
Sensitive Information Disclosure

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch more sophisticated attacks if a server respond in a way that identifies it as vulnerable. You may see hundreds of these alerts in a short period of time. If you see a HTTP 200 response to a HTTP request that generated an alert, you’ll want to investigate further. Typically, evidence of a successful attack will show your configuration files (wp-config.php, configuration.php, /etc/passwd, etc...) being served to the attacker. 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Local_File_Inclusion

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012997
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible http Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=http|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2012997; rev:4; metadata:created_at 2011_06_10, updated_at 2011_06_10;)
` 

Name : **PHP Possible http Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2011-06-10

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013014
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible zlib Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=zlib|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013014; rev:5; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible zlib Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013003
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible data Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=data|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013003; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible data Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013004
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible glob Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=glob|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013004; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible glob Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013005
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible phar Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=phar|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013005; rev:5; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible phar Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013006
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible ssh2 Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=ssh2|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013006; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible ssh2 Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013007
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible rar Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=rar|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013007; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible rar Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013008
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible ogg Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=ogg|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013008; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible ogg Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013009
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Possible expect Remote File Inclusion Attempt"; flow:established,to_server; content:".php?"; http_uri; content:"=expect|3a|//"; http_uri; reference:cve,2002-0953; reference:url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/; classtype:web-application-attack; sid:2013009; rev:4; metadata:created_at 2011_06_10, updated_at 2020_04_20;)
` 

Name : **PHP Possible expect Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,diablohorn.wordpress.com/2010/01/16/interesting-local-file-inclusion-method/

CVE reference : Not defined

Creation date : 2011-06-10

Last modified date : 2020-04-20

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011280
`#alert http $HTTP_SERVERS any -> any any (msg:"ET WEB_SERVER Phoenix Exploit Kit - Admin Login Page Detected Outbound"; flow:established,to_client; content:"<title>Phoenix Exploit's Kit - Log In</title>"; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011280; rev:3; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Phoenix Exploit Kit - Admin Login Page Detected Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013115
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Muieblackcat scanner"; flow:established,to_server; content:"GET /muieblackcat HTTP/1.1"; depth:26; classtype:attempted-recon; sid:2013115; rev:3; metadata:created_at 2011_06_24, updated_at 2011_06_24;)
` 

Name : **Muieblackcat scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-24

Last modified date : 2011-06-24

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013365
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PUT Website Defacement Attempt"; flow:established,to_server; content:"PUT"; http_method; content:"<title>.|3a 3a|[+] Defaced by "; nocase; http_client_body; classtype:web-application-attack; sid:2013365; rev:2; metadata:created_at 2011_08_05, updated_at 2020_04_20;)
` 

Name : **PUT Website Defacement Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-05

Last modified date : 2020-04-20

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101122
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /etc/passwd"; flow:to_server,established; content:"/etc/passwd"; nocase; classtype:attempted-recon; sid:2101122; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/etc/passwd** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013921
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER DNS changer cPanel attempt"; flow:to_server,established; content:"pwCfm=Dn5Ch4ng3"; http_client_body; classtype:web-application-attack; sid:2013921; rev:2; metadata:created_at 2011_11_17, updated_at 2020_04_20;)
` 

Name : **DNS changer cPanel attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-17

Last modified date : 2020-04-20

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014017
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER JBoss jmx-console Probe"; flow:to_server,established; content:"HEAD"; http_method; content:"/jmx-console/HtmlAdaptor?"; http_uri; nocase; reference:cve,2010-0738; classtype:web-application-activity; sid:2014017; rev:2; metadata:created_at 2011_12_09, updated_at 2020_04_20;)
` 

Name : **JBoss jmx-console Probe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : cve,2010-0738

CVE reference : Not defined

Creation date : 2011-12-09

Last modified date : 2020-04-20

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014018
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER JBoss jmx-console Access Control Bypass Attempt"; flow:to_server,established; content:"HEAD"; http_method; content:"/jmx-console/HtmlAdaptor?"; http_uri; nocase; content:"Runtime.getRuntime().exec("; http_uri; reference:cve,2010-0738; classtype:web-application-activity; sid:2014018; rev:2; metadata:created_at 2011_12_09, updated_at 2020_04_20;)
` 

Name : **JBoss jmx-console Access Control Bypass Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : cve,2010-0738

CVE reference : Not defined

Creation date : 2011-12-09

Last modified date : 2020-04-20

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014045
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Generic Web Server Hashing Collision Attack"; flow:established,to_server; content:"Content-Type|3A| application|2F|x-www-form-urlencoded"; nocase; http_header; isdataat:1500; pcre:"/([\w\x25]+=[\w\x25]*&){500}/OPsmi"; reference:cve,2011-3414; reference:url,events.ccc.de/congress/2011/Fahrplan/events/4680.en.html; reference:url,technet.microsoft.com/en-us/security/advisory/2659883; reference:url,blogs.technet.com/b/srd/archive/2011/12/29/asp-net-security-update-is-live.aspx; classtype:attempted-dos; sid:2014045; rev:3; metadata:created_at 2011_12_30, updated_at 2011_12_30;)
` 

Name : **Generic Web Server Hashing Collision Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2011-3414|url,events.ccc.de/congress/2011/Fahrplan/events/4680.en.html|url,technet.microsoft.com/en-us/security/advisory/2659883|url,blogs.technet.com/b/srd/archive/2011/12/29/asp-net-security-update-is-live.aspx

CVE reference : Not defined

Creation date : 2011-12-30

Last modified date : 2011-12-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014046
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Generic Web Server Hashing Collision Attack 2"; flow:established,to_server; content:"Content-Type|3A| multipart/form-data"; nocase; http_header; isdataat:5000; pcre:"/(\r\nContent-Disposition\x3a\s+form-data\x3b[^\r\n]+\r\n\r\n.+?){250}/OPsmi"; reference:cve,2011-3414; reference:url,events.ccc.de/congress/2011/Fahrplan/events/4680.en.html; reference:url,technet.microsoft.com/en-us/security/advisory/2659883; reference:url,blogs.technet.com/b/srd/archive/2011/12/29/asp-net-security-update-is-live.aspx; classtype:attempted-dos; sid:2014046; rev:3; metadata:created_at 2011_12_30, updated_at 2011_12_30;)
` 

Name : **Generic Web Server Hashing Collision Attack 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,2011-3414|url,events.ccc.de/congress/2011/Fahrplan/events/4680.en.html|url,technet.microsoft.com/en-us/security/advisory/2659883|url,blogs.technet.com/b/srd/archive/2011/12/29/asp-net-security-update-is-live.aspx

CVE reference : Not defined

Creation date : 2011-12-30

Last modified date : 2011-12-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010119
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER xp_cmdshell Attempt in Cookie"; flow:established,to_server; content:"xp_cmdshell"; nocase; http_header; pcre:"/\x0a\x0dCookie\x3a[^\n]+xp_cmdshell/i"; reference:url,www.databasejournal.com/features/mssql/article.php/3372131/Using-xpcmdshell.htm; reference:url,msdn.microsoft.com/en-us/library/ms175046.aspx; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=4072; reference:url,doc.emergingthreats.net/2010119; classtype:web-application-attack; sid:2010119; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **xp_cmdshell Attempt in Cookie** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.databasejournal.com/features/mssql/article.php/3372131/Using-xpcmdshell.htm|url,msdn.microsoft.com/en-us/library/ms175046.aspx|url,tools.cisco.com/security/center/viewAlert.x?alertId=4072|url,doc.emergingthreats.net/2010119

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014100
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ASP.NET Forms Authentication Bypass"; flow:to_server,established; content:"/CreatingUserAccounts.aspx"; http_uri; content:"CreateUserStepContainer"; content:"UserName="; distance:0; content:"%00"; distance:0; pcre:"/UserName\x3d[^\x26]+\x2500/"; reference:cve,2011-3416; classtype:attempted-user; sid:2014100; rev:3; metadata:created_at 2012_01_03, updated_at 2020_04_20;)
` 

Name : **ASP.NET Forms Authentication Bypass** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2011-3416

CVE reference : Not defined

Creation date : 2012-01-03

Last modified date : 2020-04-20

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009677
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible BASE Authentication Bypass Attempt"; flow:to_server,established; content:"BASERole="; http_header; content:"794b69ad33015df95578d5f4a19d390e"; within:40; http_header; reference:url,seclists.org/bugtraq/2009/Jun/0218.html; reference:url,seclists.org/bugtraq/2009/Jun/0217.html; reference:url,doc.emergingthreats.net/2009677; classtype:web-application-attack; sid:2009677; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible BASE Authentication Bypass Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/bugtraq/2009/Jun/0218.html|url,seclists.org/bugtraq/2009/Jun/0217.html|url,doc.emergingthreats.net/2009677

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102156
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER mod_gzip_status access"; flow:to_server,established; content:"/mod_gzip_status"; http_uri; reference:nessus,11685; classtype:web-application-activity; sid:2102156; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mod_gzip_status access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,11685

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102131
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER IISProtect access"; flow:to_server,established; content:"/iisprotect/admin/"; http_uri; nocase; reference:nessus,11661; classtype:web-application-activity; sid:2102131; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IISProtect access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,11661

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102073
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER globals.pl access"; flow:to_server,established; content:"/globals.pl"; http_uri; reference:bugtraq,2671; reference:cve,2001-0330; classtype:web-application-activity; sid:2102073; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **globals.pl access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,2671|cve,2001-0330

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102056
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER TRACE attempt"; flow:to_server,established; content:"TRACE"; http_method; reference:bugtraq,9561; reference:nessus,11213; reference:url,www.whitehatsec.com/press_releases/WH-PR-20030120.pdf; classtype:web-application-attack; sid:2102056; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TRACE attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,9561|nessus,11213|url,www.whitehatsec.com/press_releases/WH-PR-20030120.pdf

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009485
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /etc/shadow Detected in URI"; flow:to_server,established; content:"/etc/shadow"; http_uri; nocase; reference:url,en.wikipedia.org/wiki/Shadow_password; reference:url,doc.emergingthreats.net/2009485; classtype:attempted-recon; sid:2009485; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **/etc/shadow Detected in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,en.wikipedia.org/wiki/Shadow_password|url,doc.emergingthreats.net/2009485

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001365
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Alternate Data Stream source view attempt"; flow:to_server,established; content:"|3A 3A|$DATA"; http_uri; reference:url,support.microsoft.com/kb/q188806/; reference:cve,1999-0278; reference:url,doc.emergingthreats.net/2001365; classtype:web-application-activity; sid:2001365; rev:12; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Alternate Data Stream source view attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,support.microsoft.com/kb/q188806/|cve,1999-0278|url,doc.emergingthreats.net/2001365

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014296
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER eval/base64_decode Exploit Attempt Inbound"; flow:established,to_server; content:"eval|28|base64_decode|28|"; http_uri; classtype:web-application-attack; sid:2014296; rev:2; metadata:created_at 2012_02_29, updated_at 2012_02_29;)
` 

Name : **eval/base64_decode Exploit Attempt Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-02-29

Last modified date : 2012-02-29

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011424
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Using MSSQL sp_configure Command"; flow:established,to_server; content:"sp_configure"; http_uri; nocase; reference:url,technet.microsoft.com/en-us/library/ms188787.aspx; reference:url,technet.microsoft.com/en-us/library/ms190693.aspx; classtype:web-application-attack; sid:2011424; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)
` 

Name : **Possible SQL Injection Using MSSQL sp_configure Command** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,technet.microsoft.com/en-us/library/ms188787.aspx|url,technet.microsoft.com/en-us/library/ms190693.aspx

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101519
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER apache ?M=D directory list attempt"; flow:to_server,established; content:"/?M=D"; http_uri; reference:bugtraq,3009; reference:cve,2001-0731; classtype:web-application-activity; sid:2101519; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **apache ?M=D directory list attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,3009|cve,2001-0731

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101056
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Tomcat view source attempt"; flow:to_server,established; content:"%252ejsp"; http_uri; reference:bugtraq,2527; reference:cve,2001-0590; classtype:web-application-attack; sid:2101056; rev:10; metadata:created_at 2010_09_23, updated_at 2019_08_22;)
` 

Name : **Tomcat view source attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,2527|cve,2001-0590

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-08-22

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101236
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Tomcat sourcecode view attempt 3"; flow:to_server,established; content:".js%2570"; http_uri; nocase; classtype:attempted-recon; sid:2101236; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Tomcat sourcecode view attempt 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101237
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Tomcat sourcecode view attempt 2"; flow:to_server,established; content:".j%2573p"; http_uri; nocase; classtype:attempted-recon; sid:2101237; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Tomcat sourcecode view attempt 2** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101238
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL WEB_SERVER Tomcat sourcecode view attempt 1"; flow:to_server,established; content:".%256Asp"; http_uri; nocase; classtype:attempted-recon; sid:2101238; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Tomcat sourcecode view attempt 1** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101108
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Tomcat server snoop access"; flow:to_server,established; content:"/jsp/snp/"; http_uri; content:".snp"; http_uri; reference:bugtraq,1532; reference:cve,2000-0760; classtype:attempted-recon; sid:2101108; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Tomcat server snoop access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,1532|cve,2000-0760

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101055
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER Tomcat directory traversal attempt"; flow:to_server,established; content:"|00|.jsp"; http_uri; reference:bugtraq,2518; classtype:web-application-attack; sid:2101055; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Tomcat directory traversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,2518

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101145
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /~root access"; flow:to_server,established; content:"/~root"; http_uri; nocase; classtype:attempted-recon; sid:2101145; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/~root access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101489
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /~nobody access"; flow:to_server,established; content:"/~nobody"; http_uri; reference:nessus,10484; classtype:web-application-attack; sid:2101489; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/~nobody access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : nessus,10484

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101662
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /~ftp access"; flow:to_server,established; content:"/~ftp"; nocase; http_uri; classtype:attempted-recon; sid:2101662; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/~ftp access** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101129
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER .htaccess access"; flow:to_server,established; content:".htaccess"; nocase; http_uri; classtype:attempted-recon; sid:2101129; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **.htaccess access** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101285
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER msdac access"; flow:to_server,established; content:"/msdac/"; nocase; http_uri; reference:nessus,11032; classtype:web-application-activity; sid:2101285; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **msdac access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,11032

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101023
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER msadcs.dll access"; flow:to_server,established; content:"/msadcs.dll"; nocase; http_uri; reference:bugtraq,529; reference:cve,1999-1011; reference:nessus,10357; classtype:web-application-activity; sid:2101023; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **msadcs.dll access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,529|cve,1999-1011|nessus,10357

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011467
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /bin/ksh In URI Possible Shell Command Execution Attempt"; flow:established,to_server; content:"/bin/ksh"; nocase; http_uri; classtype:web-application-attack; sid:2011467; rev:5; metadata:created_at 2010_09_09, updated_at 2010_09_09;)
` 

Name : **/bin/ksh In URI Possible Shell Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-09

Last modified date : 2010-09-09

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011466
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /bin/tsh In URI Possible Shell Command Execution Attempt"; flow:established,to_server; content:"/bin/tsh"; http_uri; nocase; classtype:web-application-attack; sid:2011466; rev:5; metadata:created_at 2010_09_09, updated_at 2010_09_09;)
` 

Name : **/bin/tsh In URI Possible Shell Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-09

Last modified date : 2010-09-09

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011465
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt"; flow:established,to_server; content:"/bin/sh"; http_uri; nocase; classtype:web-application-attack; sid:2011465; rev:7; metadata:created_at 2010_10_13, updated_at 2010_10_13;)
` 

Name : **/bin/sh In URI Possible Shell Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-10-13

Last modified date : 2010-10-13

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011464
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /bin/csh In URI Possible Shell Command Execution Attempt"; flow:established,to_server; content:"/bin/csh"; nocase; http_uri; classtype:web-application-attack; sid:2011464; rev:4; metadata:created_at 2010_09_09, updated_at 2010_09_09;)
` 

Name : **/bin/csh In URI Possible Shell Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-09

Last modified date : 2010-09-09

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101603
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER DELETE attempt"; flow:to_server,established; content:"DELETE"; http_method; nocase; reference:nessus,10498; classtype:web-application-activity; sid:2101603; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DELETE attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,10498

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014886
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER IIS INDEX_ALLOCATION Auth Bypass Attempt"; flow:established,to_server; content:"|3a|$INDEX_ALLOCATION"; http_uri; nocase; reference:url,lists.grok.org.uk/pipermail/full-disclosure/2012-June/087269.html; classtype:bad-unknown; sid:2014886; rev:2; metadata:created_at 2012_06_11, updated_at 2012_06_11;)
` 

Name : **IIS INDEX_ALLOCATION Auth Bypass Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,lists.grok.org.uk/pipermail/full-disclosure/2012-June/087269.html

CVE reference : Not defined

Creation date : 2012-06-11

Last modified date : 2012-06-11

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014890
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible attempt to enumerate MS SQL Server version"; flow:established,to_server; content:"@@version"; nocase; http_uri; reference:url,support.microsoft.com/kb/321185; classtype:attempted-admin; sid:2014890; rev:2; metadata:created_at 2012_06_13, updated_at 2012_06_13;)
` 

Name : **Possible attempt to enumerate MS SQL Server version** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,support.microsoft.com/kb/321185

CVE reference : Not defined

Creation date : 2012-06-13

Last modified date : 2012-06-13

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014986
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER possible IBM Rational Directory Server (RDS) Help system href browser redirect"; flow:established,to_server; content:"/rds-help/advanced/deferredView.jsp?"; nocase; http_uri; content:"href="; nocase; http_uri; pcre:"/href=\s*(ftps?|https?|php)\:\//Ui"; reference:url,secunia.com/advisories/49627/; classtype:web-application-attack; sid:2014986; rev:2; metadata:created_at 2012_06_29, updated_at 2012_06_29;)
` 

Name : **possible IBM Rational Directory Server (RDS) Help system href browser redirect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/49627/

CVE reference : Not defined

Creation date : 2012-06-29

Last modified date : 2012-06-29

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014987
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER possible IBM Rational Directory Server (RDS) Help system href Cross Site Scripting Attempt"; flow:established,to_server; content:"/rds-help/advanced/deferredView.jsp?"; nocase; http_uri; content:"href="; nocase; http_uri; pcre:"/href\x3D.+(script|alert|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|javascript)/Ui"; reference:url,secunia.com/advisories/49627/; classtype:web-application-attack; sid:2014987; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2012_06_29, updated_at 2016_07_01;)
` 

Name : **possible IBM Rational Directory Server (RDS) Help system href Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/49627/

CVE reference : Not defined

Creation date : 2012-06-29

Last modified date : 2016-07-01

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015035
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER possible SAP Crystal Report Server 2008 path parameter Directory Traversal vulnerability"; flow:established,to_server; content:"/PerformanceManagement/jsp/qa.jsp?"; nocase; http_uri; content:"func="; nocase; http_uri; content:"root="; nocase; http_uri; content:"path="; nocase; http_uri; content:"|2e 2e 2f|"; nocase; depth:200; reference:url,1337day.com/exploits/15332; classtype:web-application-attack; sid:2015035; rev:2; metadata:created_at 2012_07_06, updated_at 2012_07_06;)
` 

Name : **possible SAP Crystal Report Server 2008 path parameter Directory Traversal vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,1337day.com/exploits/15332

CVE reference : Not defined

Creation date : 2012-07-06

Last modified date : 2012-07-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002158
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER XML-RPC for PHP Remote Code Injection"; flow:established,to_server; content:"POST"; nocase; http_method; content:"xmlrpc.php"; http_uri; content:"methodCall"; http_client_body; nocase; pcre:"/>.*?\'\s*?\)\s*?\)*?\s*?\;/PR"; reference:url,www.securityfocus.com/bid/14088/exploit; reference:cve,2005-1921; reference:url,doc.emergingthreats.net/bin/view/Main/2002158; classtype:web-application-attack; sid:2002158; rev:14; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **XML-RPC for PHP Remote Code Injection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/14088/exploit|cve,2005-1921|url,doc.emergingthreats.net/bin/view/Main/2002158

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011035
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL Injection BULK INSERT in URI to Insert File Content into Database Table"; flow:established,to_server; content:"BULK"; nocase; http_uri; content:"INSERT"; nocase; http_uri; distance:0; reference:url,msdn.microsoft.com/en-us/library/ms188365.aspx; reference:url,msdn.microsoft.com/en-us/library/ms175915.aspx; reference:url,www.sqlteam.com/article/using-bulk-insert-to-load-a-text-file; reference:url,doc.emergingthreats.net/2011035; classtype:web-application-attack; sid:2011035; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SQL Injection BULK INSERT in URI to Insert File Content into Database Table** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,msdn.microsoft.com/en-us/library/ms188365.aspx|url,msdn.microsoft.com/en-us/library/ms175915.aspx|url,www.sqlteam.com/article/using-bulk-insert-to-load-a-text-file|url,doc.emergingthreats.net/2011035

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015518
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER .PHP being served from WP 1-flash-gallery Upload DIR (likely malicious)"; flow:established,to_server; content:"/wp-content/uploads/fgallery/"; fast_pattern:11,18; nocase; http_uri; content:".php"; nocase; distance:0; http_uri; classtype:bad-unknown; sid:2015518; rev:5; metadata:created_at 2012_07_23, updated_at 2012_07_23;)
` 

Name : **.PHP being served from WP 1-flash-gallery Upload DIR (likely malicious)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-07-23

Last modified date : 2012-07-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015527
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Fake Googlebot UA 2 Inbound"; flow:established,to_server; content:"User-Agent|3a|"; http_header; content:!"Googlebot-News|0d 0a|"; within:16; http_header; content:!" Googlebot-Image/1.0|0d 0a|"; within:22; http_header; content:!" Googlebot-Video/1.0|0d 0a|"; within:22; http_header; content:"Googlebot-"; fast_pattern; http_header; nocase; distance:0; content:!"Mobile/2.1|3b| +http|3a|//www.google.com/bot.html)|0d 0a|"; within:46; http_header; pcre:"/^User-Agent\x3a[^\r\n]+?Googlebot-.+?\r$/Hmi"; reference:url,www.incapsula.com/the-incapsula-blog/item/369-was-that-really-a-google-bot-crawling-my-site; reference:url,support.google.com/webmasters/bin/answer.py?hl=en&answer=1061943; classtype:network-scan; sid:2015527; rev:2; metadata:created_at 2012_07_25, updated_at 2012_07_25;)
` 

Name : **Fake Googlebot UA 2 Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,www.incapsula.com/the-incapsula-blog/item/369-was-that-really-a-google-bot-crawling-my-site|url,support.google.com/webmasters/bin/answer.py?hl=en&answer=1061943

CVE reference : Not defined

Creation date : 2012-07-25

Last modified date : 2012-07-25

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001342
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER IIS ASP.net Auth Bypass / Canonicalization"; flow: to_server,established; content:"GET"; nocase; http_method; content:"|5C|"; http_uri;  content:".aspx"; within:100; nocase; http_uri; reference:url,doc.emergingthreats.net/2001342; reference:cve,CVE-2004-0847; classtype:web-application-attack; sid:2001342; rev:25; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IIS ASP.net Auth Bypass / Canonicalization** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2001342|cve,CVE-2004-0847

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 25

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101199
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 2301 (msg:"GPL WEB_SERVER Compaq Insight directory traversal"; flow:to_server,established; content:"../../../"; reference:arachnids,244; reference:bugtraq,282; reference:cve,1999-0771; classtype:web-application-attack; sid:2101199; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Compaq Insight directory traversal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : arachnids,244|bugtraq,282|cve,1999-0771

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101369
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /bin/ls command attempt"; flow:to_server,established; content:"/bin/ls"; http_uri; nocase; classtype:web-application-attack; sid:2101369; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/bin/ls command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101368
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /bin/ls| command attempt"; flow:to_server,established; content:"/bin/ls|7C|"; http_uri; nocase; classtype:web-application-attack; sid:2101368; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/bin/ls| command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101328
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /bin/ps command attempt"; flow:to_server,established; content:"/bin/ps"; http_uri; nocase; classtype:web-application-attack; sid:2101328; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/bin/ps command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101370
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /etc/inetd.conf access"; flow:to_server,established; content:"/etc/inetd.conf"; http_uri; nocase; classtype:web-application-activity; sid:2101370; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/etc/inetd.conf access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101371
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /etc/motd access"; flow:to_server,established; content:"/etc/motd"; http_uri; nocase; classtype:web-application-activity; sid:2101371; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/etc/motd access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101332
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /usr/bin/id command attempt"; flow:to_server,established; content:"/usr/bin/id"; http_uri; nocase; classtype:web-application-attack; sid:2101332; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/usr/bin/id command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101355
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /usr/bin/perl execution attempt"; flow:to_server,established; content:"/usr/bin/perl"; http_uri; nocase; classtype:web-application-attack; sid:2101355; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/usr/bin/perl execution attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101349
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER bin/python access attempt"; flow:to_server,established; content:"bin/python"; http_uri; nocase; classtype:web-application-attack; sid:2101349; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **bin/python access attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101350
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER python access attempt"; flow:to_server,established; content:"python "; http_uri; nocase; classtype:web-application-attack; sid:2101350; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **python access attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100920
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL WEB_SERVER datasource attempt"; flow:to_server,established; content:"CF_ISCOLDFUSIONDATASOURCE|28 29|"; nocase; reference:bugtraq,550; classtype:web-application-attack; sid:2100920; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **datasource attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,550

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100919
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL WEB_SERVER datasource password attempt"; flow:to_server,established; content:"CF_SETDATASOURCEPASSWORD|28 29|"; nocase; reference:bugtraq,550; classtype:web-application-attack; sid:2100919; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **datasource password attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,550

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100909
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL WEB_SERVER datasource username attempt"; flow:to_server,established; content:"CF_SETDATASOURCEUSERNAME|28 29|"; nocase; reference:bugtraq,550; classtype:web-application-attack; sid:2100909; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **datasource username attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,550

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100923
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"GPL WEB_SERVER getodbcin attempt"; flow:to_server,established; content:"CFUSION_GETODBCINI|28 29|"; nocase; reference:bugtraq,550; classtype:web-application-attack; sid:2100923; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **getodbcin attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,550

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101288
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /_vti_bin/ access"; flow:to_server,established; content:"/_vti_bin/"; http_uri; nocase; reference:nessus,11032; classtype:web-application-activity; sid:2101288; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/_vti_bin/ access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : nessus,11032

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100937
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER _vti_rpc access"; flow:to_server,established; content:"/_vti_rpc"; http_uri; nocase; reference:bugtraq,2144; reference:cve,2001-0096; reference:nessus,10585; classtype:web-application-activity; sid:2100937; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **_vti_rpc access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,2144|cve,2001-0096|nessus,10585

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100952
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER author.exe access"; flow:to_server,established; content:"/_vti_bin/_vti_aut/author.exe"; http_uri; nocase; classtype:web-application-activity; sid:2100952; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **author.exe access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100951
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER authors.pwd access"; flow:to_server,established; content:"/authors.pwd"; http_uri; nocase; reference:bugtraq,989; reference:cve,1999-0386; reference:nessus,10078; classtype:web-application-activity; sid:2100951; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **authors.pwd access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,989|cve,1999-0386|nessus,10078

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100958
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER service.cnf access"; flow:to_server,established; content:"/_vti_pvt/service.cnf"; http_uri; nocase; reference:bugtraq,4078; reference:nessus,10575; classtype:web-application-activity; sid:2100958; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **service.cnf access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,4078|nessus,10575

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100959
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER service.pwd"; flow:to_server,established; content:"/service.pwd"; http_uri; nocase; reference:bugtraq,1205; classtype:web-application-activity; sid:2100959; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **service.pwd** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,1205

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100961
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER services.cnf access"; flow:to_server,established; content:"/_vti_pvt/services.cnf"; http_uri; nocase; reference:bugtraq,4078; reference:nessus,10575; classtype:web-application-activity; sid:2100961; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **services.cnf access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,4078|nessus,10575

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100965
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER writeto.cnf access"; flow:to_server,established; content:"/_vti_pvt/writeto.cnf"; nocase; http_uri; reference:bugtraq,4078; reference:nessus,10575; classtype:web-application-activity; sid:2100965; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **writeto.cnf access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,4078|nessus,10575

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100994
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER /scripts/iisadmin/default.htm access"; flow:to_server,established; content:"/scripts/iisadmin/default.htm"; http_uri; nocase; classtype:web-application-attack; sid:2100994; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **/scripts/iisadmin/default.htm access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100971
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER ISAPI .printer access"; flow:to_server,established; content:".printer"; http_uri; nocase; reference:arachnids,533; reference:bugtraq,2674; reference:cve,2001-0241; reference:nessus,10661; reference:url,www.microsoft.com/technet/security/bulletin/MS01-023.mspx; classtype:web-application-activity; sid:2100971; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ISAPI .printer access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : arachnids,533|bugtraq,2674|cve,2001-0241|nessus,10661|url,www.microsoft.com/technet/security/bulletin/MS01-023.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100988
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER SAM Attempt"; flow:to_server,established; content:"sam._"; http_uri; nocase; reference:url,www.ciac.org/ciac/bulletins/h-45.shtml; classtype:web-application-attack; sid:2100988; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SAM Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.ciac.org/ciac/bulletins/h-45.shtml

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101016
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER global.asa access"; flow:to_server,established; content:"/global.asa"; http_uri; nocase; reference:cve,2000-0778; reference:nessus,10491; reference:nessus,10991; classtype:web-application-activity; sid:2101016; rev:15; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **global.asa access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : cve,2000-0778|nessus,10491|nessus,10991

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 15

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100993
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER iisadmin access"; flow:to_server,established; content:"/iisadmin"; nocase; http_uri; reference:bugtraq,189; reference:cve,1999-1538; reference:nessus,11032; classtype:web-application-attack; sid:2100993; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **iisadmin access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,189|cve,1999-1538|nessus,11032

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101071
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER .htpasswd access"; flow:to_server,established; content:".htpasswd"; nocase; classtype:web-application-attack; sid:2101071; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **.htpasswd access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101156
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER apache directory disclosure attempt"; flow:to_server,established; content:"////////"; depth:200; reference:bugtraq,2503; classtype:attempted-dos; sid:2101156; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **apache directory disclosure attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,2503

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101110
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER apache source.asp file access"; flow:to_server,established; content:"/site/eg/source.asp"; http_uri; nocase; reference:bugtraq,1457; reference:cve,2000-0628; reference:nessus,10480; classtype:attempted-recon; sid:2101110; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **apache source.asp file access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,1457|cve,2000-0628|nessus,10480

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101118
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER ls%20-l"; flow:to_server,established; content:"ls%20-l"; nocase; classtype:attempted-recon; sid:2101118; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ls%20-l** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101403
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER viewcode access"; flow:to_server,established; content:"/viewcode"; http_uri; reference:cve,1999-0737; reference:nessus,10576; reference:nessus,12048; classtype:web-application-attack; sid:2101403; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **viewcode access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,1999-0737|nessus,10576|nessus,12048

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101201
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL WEB_SERVER 403 Forbidden"; flow:from_server,established; content:"403"; http_stat_code; classtype:attempted-recon; sid:2101201; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **403 Forbidden** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015703
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Brutus Scan Inbound"; flow:established,to_server; content:"Brutus/AET"; http_user_agent; classtype:attempted-recon; sid:2015703; rev:3; metadata:created_at 2012_09_17, updated_at 2012_09_17;)
` 

Name : **Brutus Scan Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-17

Last modified date : 2012-09-17

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015481
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Compromised Wordpress Install Serving Malicious JS"; flow:established,to_client; file_data; content:"var wow"; fast_pattern; content:"Date"; distance:0; within:200; pcre:"/var wow\s*=\s*\x22[^\x22\n]+?\x22\x3b[^\x3b\n]*?Date[^\x3b\n]*?\x3b/"; reference:url,blog.unmaskparasites.com/2012/07/11/whats-in-your-wp-head/; classtype:trojan-activity; sid:2015481; rev:5; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2012_07_16, updated_at 2016_07_01;)
` 

Name : **Compromised Wordpress Install Serving Malicious JS** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : trojan-activity

URL reference : url,blog.unmaskparasites.com/2012/07/11/whats-in-your-wp-head/

CVE reference : Not defined

Creation date : 2012-07-16

Last modified date : 2016-07-01

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002667
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER sumthin scan"; flow:established,to_server; content:"GET"; nocase; http_method; content:"/sumthin"; nocase; http_uri; reference:url,www.webmasterworld.com/forum11/2100.htm; reference:url,doc.emergingthreats.net/2002667; classtype:attempted-recon; sid:2002667; rev:38; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **sumthin scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.webmasterworld.com/forum11/2100.htm|url,doc.emergingthreats.net/2002667

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 38

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014020
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Wordpress Login Bruteforcing Detected"; flow:to_server,established; content:"/wp-login.php"; nocase; http_uri; content:"POST"; http_method; content:"log|3d|"; http_client_body; content:"pwd|3d|"; http_client_body; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2014020; rev:4; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_12_12, updated_at 2016_07_01;)
` 

Name : **Wordpress Login Bruteforcing Detected** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-12

Last modified date : 2016-07-01

Rev version : 4

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015755
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Image Content-Type with Obfuscated PHP (Seen with C99 Shell)"; flow:from_server,established; content:"Content-Type|3a| image/"; http_header; file_data; content:"eval(gzinflate(base64_decode("; distance:0; fast_pattern; reference:url,malwaremustdie.blogspot.jp/2012/10/how-far-phpc99shell-malware-can-go-from.html; classtype:attempted-user; sid:2015755; rev:3; metadata:created_at 2012_10_02, updated_at 2012_10_02;)
` 

Name : **Image Content-Type with Obfuscated PHP (Seen with C99 Shell)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,malwaremustdie.blogspot.jp/2012/10/how-far-phpc99shell-malware-can-go-from.html

CVE reference : Not defined

Creation date : 2012-10-02

Last modified date : 2012-10-02

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011807
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebResource.axd access without t (time) parameter - possible ASP padding-oracle exploit"; flow:established,to_server; content:"GET"; http_method; content:"/WebResource.axd"; http_uri; nocase; content:!"&t="; http_uri; nocase; content:!"&amp|3b|t="; http_uri; nocase; detection_filter:track by_src,count 15,seconds 2; reference:url,netifera.com/research/; reference:url,www.microsoft.com/technet/security/advisory/2416728.mspx; classtype:web-application-attack; sid:2011807; rev:6; metadata:created_at 2010_10_12, updated_at 2010_10_12;)
` 

Name : **WebResource.axd access without t (time) parameter - possible ASP padding-oracle exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,netifera.com/research/|url,www.microsoft.com/technet/security/advisory/2416728.mspx

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2010-10-12

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015811
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER FaTaLisTiCz_Fx Webshell Detected"; flow:established,from_server; content:"visitz="; http_cookie; file_data; content:"FaTaLisTiCz_Fx"; classtype:web-application-activity; sid:2015811; rev:2; metadata:created_at 2012_10_18, updated_at 2012_10_18;)
` 

Name : **FaTaLisTiCz_Fx Webshell Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-10-18

Last modified date : 2012-10-18

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015917
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - D.K - Title"; flow:established,to_client; file_data; content:"<title>"; content:" - D.K "; fast_pattern; distance:0; content:"</title>"; distance:0; classtype:bad-unknown; sid:2015917; rev:2; metadata:created_at 2012_11_21, updated_at 2012_11_21;)
` 

Name : **WebShell - D.K - Title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2012-11-21

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015918
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Generic - c99shell based header"; flow:established,to_client; file_data; content:"<span>Uname<br>User<br>Php<br>Hdd<br>Cwd</span>"; classtype:attempted-user; sid:2015918; rev:2; metadata:created_at 2012_11_21, updated_at 2012_11_21;)
` 

Name : **WebShell - Generic - c99shell based header** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2012-11-21

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015919
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Generic - c99shell based header w/colons"; flow:established,to_client; file_data; content:"<span>Uname|3a|<br>User|3a|<br>Php|3a|<br>Hdd|3a|<br>Cwd|3a|</span>"; classtype:attempted-user; sid:2015919; rev:3; metadata:created_at 2012_11_21, updated_at 2012_11_21;)
` 

Name : **WebShell - Generic - c99shell based header w/colons** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2012-11-21

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015920
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - Generic - c99shell based POST structure w/multipart"; flow:established,to_server; content:"POST"; http_method; content:"form-data\; name=|22|a|22|"; http_client_body; content:"form-data\; name=|22|c|22|"; http_client_body; content:"form-data\; name=|22|p1|22|"; http_client_body; classtype:attempted-user; sid:2015920; rev:2; metadata:created_at 2012_11_21, updated_at 2012_11_21;)
` 

Name : **WebShell - Generic - c99shell based POST structure w/multipart** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2012-11-21

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015924
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - PHP eMailer"; flow:established,to_server; content:"POST"; http_method; content:"form-data|3b| name=|22|from|22|"; http_client_body; content:"form-data|3b| name=|22|realname|22|"; http_client_body; content:"form-data|3b| name=|22|amount|22|"; http_client_body; classtype:web-application-activity; sid:2015924; rev:2; metadata:created_at 2012_11_23, updated_at 2012_11_23;)
` 

Name : **WebShell - PHP eMailer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-23

Last modified date : 2012-11-23

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015925
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Unknown - self-kill"; flow:established,to_client; file_data; content:"<a href=|22|?x=selfremove|22|>[Self-Kill]</a>"; classtype:web-application-activity; sid:2015925; rev:2; metadata:created_at 2012_11_23, updated_at 2012_11_23;)
` 

Name : **WebShell - Unknown - self-kill** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-23

Last modified date : 2012-11-23

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015937
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - PostMan"; flow:established,to_server; content:"POST"; http_method; content:"form-data|3b| name=|22|formSubmited|22|"; http_client_body; content:"form-data|3b| name=|22|scriptPassword|22|"; http_client_body; classtype:misc-activity; sid:2015937; rev:7; metadata:created_at 2012_11_26, updated_at 2012_11_26;)
` 

Name : **WebShell - PostMan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-26

Last modified date : 2012-11-26

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015953
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER PIWIK Backdored Version calls home"; flow:established,to_server; content:"POST"; http_method; content:"prostoivse.com|0d 0a|"; http_header; nocase; content:"/x.php"; http_uri; content:"reff="; http_client_body; nocase; reference:url,piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/; reference:url,forum.piwik.org/read.php?2,97666; classtype:web-application-attack; sid:2015953; rev:4; metadata:created_at 2012_11_28, updated_at 2012_11_28;)
` 

Name : **PIWIK Backdored Version calls home** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/|url,forum.piwik.org/read.php?2,97666

CVE reference : Not defined

Creation date : 2012-11-28

Last modified date : 2012-11-28

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011358
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion Path Traversal (locale 1/5)"; flow:to_server,established; content:"POST"; nocase; http_method; content:"/CFIDE/wizards/common/_logintowizard.cfm"; http_uri; content:"locale=../../"; nocase; reference:url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964; reference:url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/; reference:cve,CVE-2010-2861; reference:url,www.exploit-db.com/exploits/14641/; classtype:web-application-attack; sid:2011358; rev:4; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **ColdFusion Path Traversal (locale 1/5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964|url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/|cve,CVE-2010-2861|url,www.exploit-db.com/exploits/14641/

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011359
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion Path Traversal (locale 2/5)"; flow:to_server,established; content:"POST"; http_method; content:"/CFIDE/administrator/archives/index.cfm"; nocase; http_uri; content:"locale=../../"; nocase; reference:url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964; reference:url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/; reference:cve,CVE-2010-2861; reference:url,www.exploit-db.com/exploits/14641/; classtype:web-application-attack; sid:2011359; rev:5; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **ColdFusion Path Traversal (locale 2/5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964|url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/|cve,CVE-2010-2861|url,www.exploit-db.com/exploits/14641/

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011362
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion Path Traversal (locale 5/5)"; flow:to_server,established; content:"POST"; http_method; content:"/CFIDE/administrator/enter.cfm"; http_uri; nocase; content:"locale=../../"; nocase; reference:url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964; reference:url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/; reference:cve,CVE-2010-2861; reference:url,www.exploit-db.com/exploits/14641/; classtype:web-application-attack; sid:2011362; rev:5; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **ColdFusion Path Traversal (locale 5/5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964|url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/|cve,CVE-2010-2861|url,www.exploit-db.com/exploits/14641/

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016151
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - JSP RAT"; flow:established,to_client; file_data; content:"<table id=\"filetable\" class=\"filelist\" cellspacing=\"1px\" cellpadding=\"0px\">"; classtype:attempted-user; sid:2016151; rev:3; metadata:created_at 2013_01_04, updated_at 2013_01_04;)
` 

Name : **WebShell - JSP RAT** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-04

Last modified date : 2013-01-04

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016152
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - JSP File Admin"; flow:established,to_client; file_data; content:"<h2>(L)aunch external program</h2>"; classtype:attempted-user; sid:2016152; rev:4; metadata:created_at 2013_01_04, updated_at 2013_01_04;)
` 

Name : **WebShell - JSP File Admin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-04

Last modified date : 2013-01-04

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016153
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - JSP File Admin - POST Structure - dir"; flow:established,to_server; content:"POST"; http_method; content:"dir="; http_client_body; content:"&sort="; http_client_body; content:"&command="; http_client_body; content:"&Submit="; http_client_body; classtype:attempted-user; sid:2016153; rev:3; metadata:created_at 2013_01_04, updated_at 2013_01_04;)
` 

Name : **WebShell - JSP File Admin - POST Structure - dir** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-04

Last modified date : 2013-01-04

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016183
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion adminapi access"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/CFIDE/adminapi"; http_uri; nocase; reference:url,www.adobe.com/support/security/advisories/apsa13-01.html; classtype:web-application-attack; sid:2016183; rev:4; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **ColdFusion adminapi access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.adobe.com/support/security/advisories/apsa13-01.html

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016182
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion componentutils access"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/CFIDE/componentutils"; http_uri; nocase; reference:url,www.adobe.com/support/security/advisories/apsa13-01.html; classtype:web-application-attack; sid:2016182; rev:6; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **ColdFusion componentutils access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.adobe.com/support/security/advisories/apsa13-01.html

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016184
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion administrator access"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/CFIDE/administrator"; http_uri; nocase; reference:url,www.adobe.com/support/security/advisories/apsa13-01.html; classtype:web-application-attack; sid:2016184; rev:5; metadata:created_at 2013_01_09, updated_at 2013_01_09;)
` 

Name : **ColdFusion administrator access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.adobe.com/support/security/advisories/apsa13-01.html

CVE reference : Not defined

Creation date : 2013-01-09

Last modified date : 2013-01-09

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016244
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Symlink_Sa"; flow:established,to_client; file_data; content:"<title>Symlink_Sa"; classtype:bad-unknown; sid:2016244; rev:2; metadata:created_at 2013_01_21, updated_at 2013_01_21;)
` 

Name : **WebShell - Symlink_Sa** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-21

Last modified date : 2013-01-21

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016245
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Generic - c99shell based header"; flow:established,to_client; file_data; content:"<b>Software|3a|"; content:"<b>uname -a|3a|"; content:"<b>uid="; classtype:bad-unknown; sid:2016245; rev:3; metadata:created_at 2013_01_21, updated_at 2013_01_21;)
` 

Name : **WebShell - Generic - c99shell based header** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-21

Last modified date : 2013-01-21

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016311
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Non-Standard HTML page in Joomla /com_content/ dir"; flow:established,to_server; content:"/components/com_content/"; http_uri; content:!"index.html"; nocase; within:10; http_uri; content:".html"; nocase; http_uri; distance:0; classtype:bad-unknown; sid:2016311; rev:6; metadata:created_at 2013_01_29, updated_at 2013_01_29;)
` 

Name : **Non-Standard HTML page in Joomla /com_content/ dir** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-01-29

Last modified date : 2013-01-29

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016354
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WSO WebShell Activity POST structure 2"; flow:established,to_server; content:"POST"; http_method; content:" name=|22|c|22|"; http_client_body; content:"name=|22|p1|22|"; http_client_body; fast_pattern; pcre:"/name=(?P<q>[\x22\x27])a(?P=q)[^\r\n]*\r\n[\r\n\s]+(?:S(?:e(?:lfRemove|cInfo)|tringTools|afeMode|ql)|(?:Bruteforc|Consol)e|FilesMan|Network|Logout|Php)/Pi"; classtype:attempted-user; sid:2016354; rev:3; metadata:created_at 2013_02_05, updated_at 2013_02_05;)
` 

Name : **WSO WebShell Activity POST structure 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-05

Last modified date : 2013-02-05

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016501
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - zecmd - Form"; flow:established,to_client; file_data; content:"<FORM METHOD=|22|GET|22| NAME=|22|comments|22| ACTION=|22 22|>"; classtype:attempted-user; sid:2016501; rev:2; metadata:created_at 2013_02_25, updated_at 2013_02_25;)
` 

Name : **WebShell - zecmd - Form** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-02-25

Last modified date : 2013-02-25

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016516
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - Generic - c99shell based POST structure"; flow:established,to_server; content:"POST"; http_method; content:"act="; depth:4; fast_pattern; http_client_body; content:"&d="; http_client_body; within:20; classtype:attempted-user; sid:2016516; rev:2; metadata:created_at 2013_03_04, updated_at 2013_03_04;)
` 

Name : **WebShell - Generic - c99shell based POST structure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-04

Last modified date : 2013-03-04

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016574
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - MySQL Interface - Database List"; flow:established,to_client; file_data; content:"<h1>Databases List</h1>"; classtype:bad-unknown; sid:2016574; rev:2; metadata:created_at 2013_03_13, updated_at 2013_03_13;)
` 

Name : **WebShell - MySQL Interface - Database List** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2013-03-13

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016575
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - MySQL Interface - Client Cookie mysql_web_admin*="; flow:established,to_server; content:"mysql_web_admin_"; http_cookie; classtype:bad-unknown; sid:2016575; rev:3; metadata:created_at 2013_03_13, updated_at 2013_03_13;)
` 

Name : **WebShell - MySQL Interface - Client Cookie mysql_web_admin*=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2013-03-13

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016576
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - MySQL Interface - Server Set Cookie mysql_web_admin*="; flow:established,to_client; content:"mysql_web_admin_"; http_cookie; classtype:bad-unknown; sid:2016576; rev:2; metadata:created_at 2013_03_13, updated_at 2013_03_13;)
` 

Name : **WebShell - MySQL Interface - Server Set Cookie mysql_web_admin*=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2013-03-13

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016577
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Romanian Webshell"; flow:established,to_client; file_data; content:"Incarca fisier|3a|"; content:"Exeuta comada|3a|"; classtype:bad-unknown; sid:2016577; rev:4; metadata:created_at 2013_03_13, updated_at 2013_03_13;)
` 

Name : **WebShell - Romanian Webshell** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-13

Last modified date : 2013-03-13

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016596
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection (varchar2)"; flow:established,to_server; content:"varchar2("; nocase; http_uri; reference:url,doc.emergingthreats.net/2008175; classtype:attempted-admin; sid:2016596; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2013_03_19, updated_at 2016_07_01;)
` 

Name : **Possible SQL Injection (varchar2)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2008175

CVE reference : Not defined

Creation date : 2013-03-19

Last modified date : 2016-07-01

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014140
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER LOIC Javascript DDoS Inbound"; flow:established,to_server; content:"GET"; http_method; content:"?id="; http_uri; content:"&msg="; http_uri; distance:13; within:5; pcre:"/\?id=[0-9]{13}&msg=[^&]+$/U"; threshold: type both, track by_src, count 5, seconds 60; reference:url,isc.sans.org/diary/Javascript+DDoS+Tool+Analysis/12442; reference:url,www.wired.com/threatlevel/2012/01/anons-rickroll-botnet; classtype:attempted-dos; sid:2014140; rev:5; metadata:created_at 2012_01_23, updated_at 2012_01_23;)
` 

Name : **LOIC Javascript DDoS Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,isc.sans.org/diary/Javascript+DDoS+Tool+Analysis/12442|url,www.wired.com/threatlevel/2012/01/anons-rickroll-botnet

CVE reference : Not defined

Creation date : 2012-01-23

Last modified date : 2012-01-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016664
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (mssql_query)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"mssql_query"; distance:0; classtype:bad-unknown; sid:2016664; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (mssql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016665
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (mssql_query)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"mssql_query"; distance:0; classtype:bad-unknown; sid:2016665; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (mssql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016666
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (pgsql_query)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"pgsql_query"; distance:0; classtype:bad-unknown; sid:2016666; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (pgsql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016667
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (pgsql_query)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"pgsql_query"; distance:0; classtype:bad-unknown; sid:2016667; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (pgsql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016668
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (mysql_query)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"mysql_query"; distance:0; classtype:bad-unknown; sid:2016668; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (mysql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016669
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (mysql_query)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"mysql_query"; distance:0; classtype:bad-unknown; sid:2016669; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (mysql_query)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016670
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (SqlException)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"SqlException"; distance:0; classtype:bad-unknown; sid:2016670; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (SqlException)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016671
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (SqlException)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"SqlException"; distance:0; classtype:bad-unknown; sid:2016671; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (SqlException)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016673
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (error in your SQL syntax)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"error in your SQL syntax"; distance:0; classtype:bad-unknown; sid:2016673; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (error in your SQL syntax)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016676
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (ORA-)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"ORA-"; distance:0; classtype:bad-unknown; sid:2016676; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (ORA-)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016677
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (ORA-)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"ORA-"; distance:0; classtype:bad-unknown; sid:2016677; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (ORA-)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016679
`alert http $HTTP_SERVERS any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - Simple - Title"; flow:established,to_client; file_data; content:"- Simple Shell</title>"; classtype:bad-unknown; sid:2016679; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell - Simple - Title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016681
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - netsh firewall"; flow:established,to_server; content:"netsh"; nocase; fast_pattern; http_client_body; content:"firewall"; within:15; http_client_body; classtype:bad-unknown; sid:2016681; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell Generic - netsh firewall** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016682
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - reg HKEY_LOCAL_MACHINE"; flow:established,to_server; content:"reg"; nocase; http_client_body; content:"HKEY_LOCAL_MACHINE"; nocase; within:80; http_client_body; classtype:bad-unknown; sid:2016682; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell Generic - reg HKEY_LOCAL_MACHINE** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016683
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - wget http - POST"; flow:established,to_server; content:"wget"; nocase; http_client_body; content:"http"; nocase; http_client_body; within:11; classtype:bad-unknown; sid:2016683; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell Generic - wget http - POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016684
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - JSPCMD - Form"; flow:established,to_client; file_data; content:"<FORM METHOD=\"GET\" NAME=\"comments\" ACTION=\"\">"; classtype:bad-unknown; sid:2016684; rev:2; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell - JSPCMD - Form** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016674
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (ERROR syntax error at or near)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"ERROR|3a|  syntax error at or near"; distance:0; classtype:bad-unknown; sid:2016674; rev:3; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 200 Response (ERROR syntax error at or near)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016675
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 500 Response (ERROR syntax error at or near)"; flow:from_server,established; content:"500"; http_stat_code; file_data; content:"ERROR|3a|  syntax error at or near"; distance:0; classtype:bad-unknown; sid:2016675; rev:3; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **SQL Errors in HTTP 500 Response (ERROR syntax error at or near)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016689
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - MySQL Interface - Auth Prompt"; flow:established,to_client; file_data; content:"bG9nb25fc3VibWl0"; classtype:bad-unknown; sid:2016689; rev:2; metadata:created_at 2013_04_01, updated_at 2013_04_01;)
` 

Name : **WebShell - MySQL Interface - Auth Prompt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-01

Last modified date : 2013-04-01

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016760
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - PHPShell - Comment"; flow:established,to_client; file_data; content:"<!-- PHPShell "; classtype:attempted-user; sid:2016760; rev:2; metadata:created_at 2013_04_16, updated_at 2013_04_16;)
` 

Name : **WebShell - PHPShell - Comment** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-16

Last modified date : 2013-04-16

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016761
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - PHPShell - Haxplorer URI"; flow:established,to_server; content:".php?&s=r&cmd=dir&dir="; http_uri; classtype:attempted-user; sid:2016761; rev:2; metadata:created_at 2013_04_16, updated_at 2013_04_16;)
` 

Name : **WebShell - PHPShell - Haxplorer URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-16

Last modified date : 2013-04-16

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016762
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - PHPShell - PHPKonsole URI"; flow:established,to_server; content:".php?&s=r&cmd=con"; http_uri; classtype:attempted-user; sid:2016762; rev:2; metadata:created_at 2013_04_16, updated_at 2013_04_16;)
` 

Name : **WebShell - PHPShell - PHPKonsole URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-16

Last modified date : 2013-04-16

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016788
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Wordpress Super Cache Plugin PHP Injection mfunc"; flow:established,to_server; content:"POST"; http_method; content:"comment"; http_client_body; nocase; content:"mfunc"; fast_pattern; http_client_body; nocase; distance:0; pcre:"/(?:%3C%21|\<\!)--[\r\n\s]*?mfunc/Pi"; classtype:attempted-user; sid:2016788; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2013_04_26, updated_at 2016_07_01;)
` 

Name : **Possible Wordpress Super Cache Plugin PHP Injection mfunc** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-26

Last modified date : 2016-07-01

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016789
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Wordpress Super Cache Plugin PHP Injection mclude"; flow:established,to_server; content:"POST"; http_method; content:"comment"; http_client_body; nocase; content:"mclude"; fast_pattern; http_client_body; nocase; distance:0; pcre:"/(?:%3C%21|\<\!)--[\r\n\s]*?mclude/Pi"; classtype:attempted-user; sid:2016789; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2013_04_26, updated_at 2016_07_01;)
` 

Name : **Possible Wordpress Super Cache Plugin PHP Injection mclude** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-26

Last modified date : 2016-07-01

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016790
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Wordpress Super Cache Plugin PHP Injection dynamic-cached-content"; flow:established,to_server; content:"POST"; http_method; content:"comment"; http_client_body; nocase; content:"dynamic-cached-content"; fast_pattern; http_client_body; nocase; distance:0; pcre:"/(?:%3C%21|\<\!)--[\r\n\s]*?dynamic-cached-content/Pi"; classtype:attempted-user; sid:2016790; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2013_04_26, updated_at 2016_07_01;)
` 

Name : **Possible Wordpress Super Cache Plugin PHP Injection dynamic-cached-content** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-26

Last modified date : 2016-07-01

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016792
`alert http $EXTERNAL_NET any -> $HOME_NET 8880 (msg:"ET WEB_SERVER Plesk Panel Possible HTTP_AUTH_LOGIN SQLi CVE-2012-1557"; flow:established,to_server; content:"POST"; http_method; content:"/enterprise/control/agent.php"; http_uri; content:"HTTP_AUTH_LOGIN|3a|"; http_header; pcre:"/^[^\r\n]*?[\x27\x22\t\\%\x00\x08\x26]/HR"; reference:cve,CVE-2012-1557; classtype:attempted-user; sid:2016792; rev:3; metadata:created_at 2013_04_26, updated_at 2013_04_26;)
` 

Name : **Plesk Panel Possible HTTP_AUTH_LOGIN SQLi CVE-2012-1557** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,CVE-2012-1557

CVE reference : Not defined

Creation date : 2013-04-26

Last modified date : 2013-04-26

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014352
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection Attempt char() Danmec related"; flow:established,to_server; content:"CHAR("; http_uri; nocase; pcre:"/CHAR\([0-9]{2,3}\)char\([^\x0d\x0a\x20]{98}/Ui"; classtype:attempted-admin; sid:2014352; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2012_03_09, updated_at 2016_07_01;)
` 

Name : **Possible SQL Injection Attempt char() Danmec related** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-09

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016836
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion password.properties access"; flow:established,to_server; content:"GET"; http_method; nocase; content:"password.properties"; http_uri; nocase; reference:url,cxsecurity.com/issue/WLB-2013050065; classtype:web-application-attack; sid:2016836; rev:3; metadata:created_at 2013_05_08, updated_at 2013_05_08;)
` 

Name : **ColdFusion password.properties access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,cxsecurity.com/issue/WLB-2013050065

CVE reference : Not defined

Creation date : 2013-05-08

Last modified date : 2013-05-08

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016841
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER  ColdFusion path disclosure to get the absolute path"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/administrator/analyzer/index.cfm"; http_uri; nocase; content:"|2e 2e 2f|"; http_raw_uri; reference:url,www.exploit-db.com/exploits/25305/; classtype:web-application-attack; sid:2016841; rev:4; metadata:created_at 2013_05_09, updated_at 2013_05_09;)
` 

Name : ** ColdFusion path disclosure to get the absolute path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.exploit-db.com/exploits/25305/

CVE reference : Not defined

Creation date : 2013-05-09

Last modified date : 2013-05-09

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016842
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion scheduletasks access"; flow:established,to_server; content:"/CFIDE/administrator/scheduler/scheduletasks.cfm"; http_uri; nocase; reference:url,exploit-db.com/exploits/24946/; classtype:web-application-attack; sid:2016842; rev:2; metadata:created_at 2013_05_14, updated_at 2013_05_14;)
` 

Name : **ColdFusion scheduletasks access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,exploit-db.com/exploits/24946/

CVE reference : Not defined

Creation date : 2013-05-14

Last modified date : 2013-05-14

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016843
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion scheduleedit access"; flow:established,to_server; content:"/CFIDE/administrator/scheduler/scheduleedit.cfm"; http_uri; nocase; reference:url,exploit-db.com/exploits/24946/; classtype:web-application-attack; sid:2016843; rev:2; metadata:created_at 2013_05_14, updated_at 2013_05_14;)
` 

Name : **ColdFusion scheduleedit access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,exploit-db.com/exploits/24946/

CVE reference : Not defined

Creation date : 2013-05-14

Last modified date : 2013-05-14

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016845
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HTTPing Usage Inbound"; flow:established,to_server; content:"HTTPing"; depth:7; http_user_agent; reference:url,www.vanheusden.com/httping/; classtype:policy-violation; sid:2016845; rev:3; metadata:created_at 2013_05_14, updated_at 2013_05_14;)
` 

Name : **HTTPing Usage Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.vanheusden.com/httping/

CVE reference : Not defined

Creation date : 2013-05-14

Last modified date : 2013-05-14

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016937
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL Injection List Priveleges Attempt"; flow:established,to_server; content:"SELECT"; http_uri; nocase; content:"PRIV"; http_uri; nocase; distance:0; pcre:"/\bSELECT.*?\bPRIV/Ui"; reference:url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet; classtype:web-application-attack; sid:2016937; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2013_05_28, updated_at 2016_07_01;)
` 

Name : **SQL Injection List Priveleges Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

CVE reference : Not defined

Creation date : 2013-05-28

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016983
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Access to /phppath/php Possible Plesk 0-day Exploit June 05 2013"; flow:established,to_server; content:"/phppath/php"; http_uri; pcre:"/\/phppath\/php\b/Ui"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:attempted-admin; sid:2016983; rev:2; metadata:created_at 2013_06_05, updated_at 2013_06_05;)
` 

Name : **Access to /phppath/php Possible Plesk 0-day Exploit June 05 2013** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2013-06-05

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017054
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - ELF File Uploaded"; flow:established,to_server; content:"|7F|ELF"; http_client_body; classtype:bad-unknown; sid:2017054; rev:2; metadata:created_at 2013_06_21, updated_at 2013_06_21;)
` 

Name : **WebShell Generic - ELF File Uploaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-06-21

Last modified date : 2013-06-21

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017083
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - GODSpy - GOD Hacker"; flow:established,to_client; file_data; content:"GOD Hacker"; classtype:trojan-activity; sid:2017083; rev:2; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - GODSpy - GOD Hacker** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017085
`alert http any any -> any any (msg:"ET WEB_SERVER WebShell - GODSpy - Cookie"; flow:established; content:"godid="; http_cookie; classtype:trojan-activity; sid:2017085; rev:2; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - GODSpy - Cookie** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017087
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - GODSpy - Auth Prompt"; flow:established,to_client; file_data; content:"name=|22|haz|22| value=|22|pasa|22|>"; classtype:trojan-activity; sid:2017087; rev:3; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - GODSpy - Auth Prompt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017088
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - GODSPy - Auth Creds"; flow:established,to_server; content:"ctr="; http_client_body; content:"haz=pasa"; http_client_body; classtype:trojan-activity; sid:2017088; rev:2; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - GODSPy - Auth Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017089
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Pouya - Pouya_Server Shell"; flow:established,to_client; file_data; content:"Pouya_Server Shell"; classtype:trojan-activity; sid:2017089; rev:2; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - Pouya - Pouya_Server Shell** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017090
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - Pouya - URI - raiz"; flow:established,to_server; content:".asp?raiz="; http_uri; classtype:trojan-activity; sid:2017090; rev:2; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - Pouya - URI - raiz** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017084
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - GODSpy - GODSpy title"; flow:established,to_client; file_data; content:"GODSpy</title>"; classtype:trojan-activity; sid:2017084; rev:3; metadata:created_at 2013_07_02, updated_at 2013_07_02;)
` 

Name : **WebShell - GODSpy - GODSpy title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2013-07-02

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017146
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HTTP Request Smuggling Attempt - Double Content-Length Headers"; flow:established,to_server; content:"Content-Length|3A|"; http_header; content:"Content-Length|3A|"; http_header; within:100; reference:url,www.owasp.org/index.php/HTTP_Request_Smuggling; classtype:web-application-attack; sid:2017146; rev:3; metadata:created_at 2013_07_12, updated_at 2013_07_12;)
` 

Name : **HTTP Request Smuggling Attempt - Double Content-Length Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/HTTP_Request_Smuggling

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2013-07-12

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017147
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HTTP Request Smuggling Attempt - Two Transfer-Encoding Values Specified"; flow:established,to_server; content:"Transfer-Encoding"; http_header; content:"Transfer-Encoding"; http_header; within:100; reference:url,www.owasp.org/index.php/HTTP_Request_Smuggling; classtype:web-application-attack; sid:2017147; rev:2; metadata:created_at 2013_07_12, updated_at 2013_07_12;)
` 

Name : **HTTP Request Smuggling Attempt - Two Transfer-Encoding Values Specified** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/HTTP_Request_Smuggling

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2013-07-12

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017260
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - ASP File Uploaded"; flow:established,to_server; content:"|0D 0A|"; http_client_body; content:"<%"; within:5; http_client_body; fast_pattern; content:"%>"; http_client_body; distance:0; pcre:"/<%[\x00-\x7f]{20}/P"; classtype:trojan-activity; sid:2017260; rev:11; metadata:created_at 2013_07_31, updated_at 2013_07_31;)
` 

Name : **WebShell Generic - ASP File Uploaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-31

Last modified date : 2013-07-31

Rev version : 11

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017293
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER - EXE File Uploaded - Hex Encoded"; flow:established,to_server; content:"4d5a"; nocase; http_client_body; content:"50450000"; distance:0; http_client_body; classtype:bad-unknown; sid:2017293; rev:2; metadata:created_at 2013_08_06, updated_at 2013_08_06;)
` 

Name : **- EXE File Uploaded - Hex Encoded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-06

Last modified date : 2013-08-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017280
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible OpenX Backdoor Backdoor Access POST to flowplayer"; flow:established,to_server; content:"POST"; http_method; nocase; content:"/flowplayer-3.1.1.min.js"; http_uri; nocase; reference:url,blog.sucuri.net/2013/08/openx-org-compromised-and-downloads-injected-with-a-backdoor.html; classtype:trojan-activity; sid:2017280; rev:3; metadata:created_at 2013_08_06, updated_at 2013_08_06;)
` 

Name : **Possible OpenX Backdoor Backdoor Access POST to flowplayer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.sucuri.net/2013/08/openx-org-compromised-and-downloads-injected-with-a-backdoor.html

CVE reference : Not defined

Creation date : 2013-08-06

Last modified date : 2013-08-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002865
`#alert http $EXTERNAL_NET any -> $HOME_NET 8300 (msg:"ET WEB_SERVER Novell GroupWise Messenger Accept Language Buffer Overflow"; flow:established,to_server; content:"Accept-Language"; nocase; pcre:"/^Accept-Language\:[^\n]*?[^,\;\n]{17}/mi"; reference:cve,2006-0992; reference:bugtraq,17503; reference:url,doc.emergingthreats.net/2002865; classtype:attempted-user; sid:2002865; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Novell GroupWise Messenger Accept Language Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2006-0992|bugtraq,17503|url,doc.emergingthreats.net/2002865

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017330
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQLi - SELECT and sysobject"; flow:established,to_server; content:"SELECT"; nocase; content:"sysobjects"; distance:0; nocase; classtype:attempted-admin; sid:2017330; rev:2; metadata:created_at 2013_08_14, updated_at 2013_08_14;)
` 

Name : **SQLi - SELECT and sysobject** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-14

Last modified date : 2013-08-14

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017337
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ATTACKER SQLi - SELECT and Schema Columns"; flow:established,to_server; content:"SELECT"; nocase; content:"information_schema.columns"; distance:0; nocase; classtype:attempted-user; sid:2017337; rev:2; metadata:created_at 2013_08_19, updated_at 2013_08_19;)
` 

Name : **ATTACKER SQLi - SELECT and Schema Columns** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-19

Last modified date : 2013-08-19

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017155
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirect"; flow:established,to_server;  content:".action?"; http_uri; content:"redirect|3a|"; http_uri; distance:0; content:"{"; http_uri; distance:0; pcre:"/[\?&]redirect\x3a/U"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017155; rev:4; metadata:created_at 2013_07_16, updated_at 2013_07_16;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-16

Last modified date : 2013-07-16

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017156
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirectAction"; flow:established,to_server; content:".action?"; http_uri; content:"redirectAction|3a|"; distance:0; http_uri; content:"{"; http_uri; distance:0; pcre:"/[\?&]redirectAction\x3a/U"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017156; rev:4; metadata:created_at 2013_07_16, updated_at 2013_07_16;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirectAction** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-16

Last modified date : 2013-07-16

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017157
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 action"; flow:established,to_server;  content:".action?"; http_uri; content:"action|3a|"; http_uri; distance:0; content:"{"; http_uri; distance:0; pcre:"/[\?&]action\x3a/U"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017157; rev:4; metadata:created_at 2013_07_16, updated_at 2013_07_16;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 action** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-16

Last modified date : 2013-07-16

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102091
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER WEBDAV nessus safe scan attempt"; flow:to_server,established; content:"SEARCH"; http_method; content:"/"; http_uri; urilen:1; content:" HTTP/1.1|0D 0A|Host|3A|"; content:"|0D 0A 0D 0A|"; within:255; reference:bugtraq,7116; reference:cve,2003-0109; reference:nessus,11412; reference:nessus,11413; reference:url,www.microsoft.com/technet/security/bulletin/ms03-007.mspx; classtype:attempted-admin; sid:2102091; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **WEBDAV nessus safe scan attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,7116|cve,2003-0109|nessus,11412|nessus,11413|url,www.microsoft.com/technet/security/bulletin/ms03-007.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017390
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - ASPyder - File Browser - Interface"; flow:established,to_client; file_data; content:"document.myform.txtpath.value"; classtype:trojan-activity; sid:2017390; rev:3; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder - File Browser - Interface** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017391
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - ASPyder - Auth Prompt"; flow:established,to_client; file_data; content:"<INPUT type=password name=code >"; classtype:trojan-activity; sid:2017391; rev:2; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder - Auth Prompt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017392
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - ASPyder - File Browser - POST Structure"; flow:established,to_server; content:"POST"; http_method; nocase; content:"txtpath="; http_client_body; depth:8; content:"&cmd="; http_client_body; classtype:trojan-activity; sid:2017392; rev:2; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder - File Browser - POST Structure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017393
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - ASPyder -File Upload - POST Structure"; flow:established,to_server; content:"POST"; http_method; nocase; content:"?upload=@&txtpath="; http_uri; content:"Upload !"; http_client_body; classtype:trojan-activity; sid:2017393; rev:2; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder -File Upload - POST Structure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017394
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - ASPyder - File Upload - Response"; flow:established,to_client; file_data; content:"<title>ASPYDrvsInfo</title>"; classtype:trojan-activity; sid:2017394; rev:2; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder - File Upload - Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017604
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER PHP WebShell Embedded In GIF (OUTBOUND)"; flow:established,to_client; file_data; content:"GIF89"; within:5; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017604; rev:2; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In GIF (OUTBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017605
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER PHP WebShell Embedded In JPG (OUTBOUND)"; flow:established,to_client; file_data; content:"JFIF|00|"; distance:6; within:5; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017605; rev:2; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In JPG (OUTBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017606
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER PHP WebShell Embedded In PNG (OUTBOUND)"; flow:established,to_client; file_data; content:"PNG|0D 0A 1A 0A|"; distance:1; within:7; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017606; rev:2; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In PNG (OUTBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017607
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP WebShell Embedded In GIF (INBOUND)"; flow:established,from_server; file_data; content:"GIF89"; within:5; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017607; rev:2; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In GIF (INBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017608
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP WebShell Embedded In JPG (INBOUND)"; flow:established,from_server; file_data; content:"JFIF|00|"; distance:6; within:5; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017608; rev:2; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In JPG (INBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017609
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP WebShell Embedded In PNG (INBOUND)"; flow:established,from_server; file_data; content:"PNG|0D 0A 1A 0A|"; distance:1; within:7; content:"<?php"; fast_pattern; distance:0; reference:url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html; classtype:successful-admin; sid:2017609; rev:3; metadata:created_at 2013_10_17, updated_at 2013_10_17;)
` 

Name : **PHP WebShell Embedded In PNG (INBOUND)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2013/10/hiding-webshell-backdoor-code-in-image-files.html

CVE reference : Not defined

Creation date : 2013-10-17

Last modified date : 2013-10-17

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017641
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Encrypted Webshell in POST"; flow:established,to_server; content:"POST"; http_method; content:"eval"; http_client_body; content:"mcrypt_decrypt"; http_client_body; distance:0; reference:url,blog.sucuri.net/2013/10/backdoor-evasion-using-encrypted-content.html; classtype:bad-unknown; sid:2017641; rev:3; metadata:created_at 2013_10_28, updated_at 2013_10_28;)
` 

Name : **Possible Encrypted Webshell in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blog.sucuri.net/2013/10/backdoor-evasion-using-encrypted-content.html

CVE reference : Not defined

Creation date : 2013-10-28

Last modified date : 2013-10-28

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017684
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SUPERMICRO IPMI login.cgi Name Parameter Buffer Overflow Attempt CVE-2013-3621"; flow:established,to_server; content:"POST"; http_method; nocase; content:"/cgi/login.cgi"; http_uri; nocase; content:"name="; nocase; http_client_body; content:"pwd="; http_client_body; nocase; pcre:"/(?:^|[\n\&])pwd=/Pi"; pcre:"/(?:^|[\n\&])name=(?:%\d{2}|[^%&]){129}/Pi"; reference:cve,CVE-2013-3621; reference:url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities; classtype:attempted-admin; sid:2017684; rev:2; metadata:created_at 2013_11_07, updated_at 2013_11_07;)
` 

Name : **Possible SUPERMICRO IPMI login.cgi Name Parameter Buffer Overflow Attempt CVE-2013-3621** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CVE-2013-3621|url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities

CVE reference : Not defined

Creation date : 2013-11-07

Last modified date : 2013-11-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017685
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SUPERMICRO IPMI login.cgi PWD Parameter Buffer Overflow Attempt CVE-2013-3621"; flow:established,to_server; content:"POST"; http_method; nocase; content:"/cgi/login.cgi"; http_uri; nocase; content:"name="; http_client_body; nocase; content:"pwd="; http_client_body; nocase; pcre:"/(?:^|[\n\&])name=/Pi"; pcre:"/(?:^|[\n\&])pwd=(?:%\d{2}|[^%&]){25}/Pi"; reference:cve,CVE-2013-3621; reference:url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities; classtype:attempted-admin; sid:2017685; rev:2; metadata:created_at 2013_11_07, updated_at 2013_11_07;)
` 

Name : **Possible SUPERMICRO IPMI login.cgi PWD Parameter Buffer Overflow Attempt CVE-2013-3621** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CVE-2013-3621|url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities

CVE reference : Not defined

Creation date : 2013-11-07

Last modified date : 2013-11-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017686
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SUPERMICRO IPMI close_window.cgi sess_sid Parameter Buffer Overflow Attempt CVE-2013-3623"; flow:established,to_server; content:"POST"; http_method; nocase; content:"/cgi/close_window.cgi"; http_uri; nocase; content:"sess_sid="; http_client_body; nocase; pcre:"/(?:^|[\n\&])sess_sid=(?:%\d{2}|[^%&]){21}/P"; reference:cve,CVE-2013-3623; reference:url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities; classtype:attempted-admin; sid:2017686; rev:2; metadata:created_at 2013_11_07, updated_at 2013_11_07;)
` 

Name : **Possible SUPERMICRO IPMI close_window.cgi sess_sid Parameter Buffer Overflow Attempt CVE-2013-3623** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CVE-2013-3623|url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities

CVE reference : Not defined

Creation date : 2013-11-07

Last modified date : 2013-11-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017687
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SUPERMICRO IPMI close_window.cgi ACT Parameter Buffer Overflow Attempt CVE-2013-3623"; flow:established,to_server; content:"POST"; http_method; nocase; content:"/cgi/close_window.cgi"; http_uri; nocase; content:"ACT="; http_client_body; nocase; pcre:"/(?:^|[\n\&])ACT=(?:%\d{2}|[^%&]){21}/Pi"; reference:cve,CVE-2013-3623; reference:url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities; classtype:attempted-admin; sid:2017687; rev:2; metadata:created_at 2013_11_07, updated_at 2013_11_07;)
` 

Name : **Possible SUPERMICRO IPMI close_window.cgi ACT Parameter Buffer Overflow Attempt CVE-2013-3623** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,CVE-2013-3623|url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities

CVE reference : Not defined

Creation date : 2013-11-07

Last modified date : 2013-11-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017688
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SUPERMICRO IPMI url_redirect.cgi Directory Traversal Attempt"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/cgi/url_redirect.cgi"; http_uri; nocase; content:"|2e 2e 2f|"; http_raw_uri; reference:url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities; classtype:attempted-admin; sid:2017688; rev:2; metadata:created_at 2013_11_07, updated_at 2013_11_07;)
` 

Name : **Possible SUPERMICRO IPMI url_redirect.cgi Directory Traversal Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities

CVE reference : Not defined

Creation date : 2013-11-07

Last modified date : 2013-11-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017803
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible WebLogic Admin Login With Default Creds"; flow:to_server,established; content:"POST"; nocase; http_method; content:"/console/j_security_check"; http_uri; nocase; content:"j_username=system"; http_client_body; nocase; content:"j_password=Passw0rd"; http_client_body; reference:url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf; classtype:attempted-admin; sid:2017803; rev:4; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible WebLogic Admin Login With Default Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017804
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible WebLogic Admin Login With Default Creds"; flow:to_server,established; content:"POST"; nocase; http_method; content:"/console/j_security_check"; http_uri; nocase; content:"j_username=system"; http_client_body; content:"j_password=password"; http_client_body; reference:url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf; classtype:attempted-admin; sid:2017804; rev:3; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible WebLogic Admin Login With Default Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017805
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible WebLogic Monitor Login With Default Creds"; flow:to_server,established; content:"POST"; nocase; http_method; content:"/console/j_security_check"; http_uri; nocase; content:"j_username=monitor"; http_client_body; content:"j_password=password"; http_client_body; reference:url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf; classtype:attempted-user; sid:2017805; rev:3; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible WebLogic Monitor Login With Default Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017806
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible WebLogic Operator Login With Default Creds"; flow:to_server,established; content:"POST"; nocase; http_method; content:"/console/j_security_check"; http_uri; nocase; content:"j_username=operator"; http_client_body; content:"j_password=password"; http_client_body; reference:url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf; classtype:attempted-user; sid:2017806; rev:2; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible WebLogic Operator Login With Default Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,media.blackhat.com/us-13/US-13-Polyakov-Practical-Pentesting-of-ERPs-and-Business-Applications-Slides.pdf

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017807
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible MySQL SQLi User-Dump Attempt"; flow:to_server,established; content:"select"; nocase; http_uri; content:"mysql.user"; http_uri; nocase; distance:1; reference:url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet; classtype:web-application-attack; sid:2017807; rev:3; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible MySQL SQLi User-Dump Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017808
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access"; flow:to_server,established; content:"information_schema"; nocase; http_uri; reference:url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet; classtype:web-application-attack; sid:2017808; rev:2; metadata:created_at 2013_12_06, updated_at 2013_12_06;)
` 

Name : **Possible MySQL SQLi Attempt Information Schema Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

CVE reference : Not defined

Creation date : 2013-12-06

Last modified date : 2013-12-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017828
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Perl/Mambo.WebShell Spreader IRC Scanning Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Scanning"; fast_pattern; within:50; content:"for open ports."; within:40; classtype:trojan-activity; sid:2017828; rev:2; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Perl/Mambo.WebShell Spreader IRC Scanning Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017829
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Perl/Mambo.WebShell Spreader IRC Open Ports Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Open port(s)|3A| "; fast_pattern; within:50; classtype:trojan-activity; sid:2017829; rev:2; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Perl/Mambo.WebShell Spreader IRC Open Ports Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017830
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Perl/Mambo.WebShell Spreader IRC No Open Ports Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"No open ports found"; fast_pattern; within:50; classtype:trojan-activity; sid:2017830; rev:1; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Perl/Mambo.WebShell Spreader IRC No Open Ports Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 1

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017831
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Mambo.PerlBot Spreader IRC DDOS Attacking Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Attacking"; within:50; fast_pattern; classtype:trojan-activity; sid:2017831; rev:2; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Mambo.PerlBot Spreader IRC DDOS Attacking Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017832
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Mambo.PerlBot Spreader IRC DDOS Attack Done Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Attack"; fast_pattern; within:50; content:"done"; within:8; classtype:trojan-activity; sid:2017832; rev:1; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Mambo.PerlBot Spreader IRC DDOS Attack Done Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 1

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017833
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Mambo.PerlBot Spreader IRC DDOS PerlBot Version Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"perlb0t ver"; within:50; classtype:trojan-activity; sid:2017833; rev:2; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Mambo.PerlBot Spreader IRC DDOS PerlBot Version Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017834
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Mambo.PerlBot Spreader IRC DDOS Mambo Scanning Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Scanning for unpatched mambo for"; within:80; classtype:trojan-activity; sid:2017834; rev:2; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Mambo.PerlBot Spreader IRC DDOS Mambo Scanning Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017835
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Mambo.PerlBot Spreader IRC DDOS Exploited Message"; flow:established,to_server; content:"PRIVMSG|20|"; content:"Exploited"; within:50; content:"boxes in"; within:30; classtype:trojan-activity; sid:2017835; rev:3; metadata:created_at 2013_12_09, updated_at 2013_12_09;)
` 

Name : **Mambo.PerlBot Spreader IRC DDOS Exploited Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2013-12-09

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017951
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER ATTACKER WebShell - PHP Offender - Title"; flow:established,to_client; file_data; content:"<title>PHP Shell offender</title>"; nocase; classtype:web-application-attack; sid:2017951; rev:3; metadata:created_at 2014_01_10, updated_at 2014_01_10;)
` 

Name : **ATTACKER WebShell - PHP Offender - Title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-01-10

Last modified date : 2014-01-10

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017952
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ATTACKER WebShell - PHP Offender - POST Command"; flow:established,to_server; content:"work_dir="; http_client_body; content:"command="; http_client_body; content:"submit_btn=Execute+Command"; http_client_body; classtype:web-application-attack; sid:2017952; rev:2; metadata:created_at 2014_01_10, updated_at 2014_01_10;)
` 

Name : **ATTACKER WebShell - PHP Offender - POST Command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-01-10

Last modified date : 2014-01-10

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018092
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Oracle Reports Forms RCE CVE-2012-3152"; flow:established,to_server; content:"/reports/rwservlet?"; http_uri; nocase; content:"JOBTYPE"; http_uri; nocase; content:"rwurl"; nocase; http_uri; content:"URLPARAMETER"; http_uri; nocase; pcre:"/URLPARAMETER\s*?=\s*?[\x22\x27]?(?:f(?:ile|tp)|gopher|https?|mailto)\s*?\x3a/Ui"; reference:url,netinfiltration.com; classtype:web-application-attack; sid:2018092; rev:2; metadata:created_at 2014_02_06, updated_at 2014_02_06;)
` 

Name : **Possible Oracle Reports Forms RCE CVE-2012-3152** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,netinfiltration.com

CVE reference : Not defined

Creation date : 2014-02-06

Last modified date : 2014-02-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018093
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Oracle Reports Parse Query Returned Creds CVE-2012-3153"; flow:established,to_client; file_data; content:"Result Reports Server Command"; content:"userid="; distance:0; content:"/"; distance:0; content:"@"; distance:0; reference:url,netinfiltration.com; classtype:web-application-attack; sid:2018093; rev:2; metadata:created_at 2014_02_06, updated_at 2014_02_06;)
` 

Name : **Oracle Reports Parse Query Returned Creds CVE-2012-3153** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,netinfiltration.com

CVE reference : Not defined

Creation date : 2014-02-06

Last modified date : 2014-02-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018118
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Recon-ng User-Agent"; flow: established,to_server; content:"Recon-ng"; http_user_agent; reference:url,itbucket.org/LaNMaSteR53/recon-ng/overview; classtype:attempted-recon; sid:2018118; rev:3; metadata:created_at 2014_02_12, updated_at 2014_02_12;)
` 

Name : **Recon-ng User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,itbucket.org/LaNMaSteR53/recon-ng/overview

CVE reference : Not defined

Creation date : 2014-02-12

Last modified date : 2014-02-12

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015526
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Fake Googlebot UA 1 Inbound"; flow:established,to_server; content:"User-Agent|3a|"; http_header; content:!" Mozilla/5.0 (compatible|3b| Googlebot/2.1|3b| +http|3a|//www.google.com/bot.html)|0d 0a|"; http_header; within:75; content:!" Googlebot/2.1 (+http|3a|//www.google.com/bot.html)|0d 0a|"; http_header; within:50; content:"Googlebot"; fast_pattern; http_header; nocase; distance:0; pcre:"/^User-Agent\x3a[^\r\n]+?Googlebot[^\-].+?\r$/Hmi"; reference:url,www.incapsula.com/the-incapsula-blog/item/369-was-that-really-a-google-bot-crawling-my-site; reference:url,support.google.com/webmasters/bin/answer.py?hl=en&answer=1061943; classtype:bad-unknown; sid:2015526; rev:4; metadata:created_at 2012_07_25, updated_at 2012_07_25;)
` 

Name : **Fake Googlebot UA 1 Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.incapsula.com/the-incapsula-blog/item/369-was-that-really-a-google-bot-crawling-my-site|url,support.google.com/webmasters/bin/answer.py?hl=en&answer=1061943

CVE reference : Not defined

Creation date : 2012-07-25

Last modified date : 2012-07-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018290
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WEBSHELL CFM Shell Access"; flow:established,from_server; file_data; content:"<title>CFM shell"; nocase; reference:url,blog.spiderlabs.com/2014/03/coldfusion-admin-compromise-analysis-cve-2010-2861.html; classtype:successful-admin; sid:2018290; rev:2; metadata:created_at 2014_03_18, updated_at 2014_03_18;)
` 

Name : **WEBSHELL CFM Shell Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.spiderlabs.com/2014/03/coldfusion-admin-compromise-analysis-cve-2010-2861.html

CVE reference : Not defined

Creation date : 2014-03-18

Last modified date : 2014-03-18

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017183
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell ASPXShell - Title"; flow:established,to_client; file_data; content:"<title>"; content:"ASPX Shell"; fast_pattern; nocase;  content:"</title>"; distance:0; classtype:trojan-activity; sid:2017183; rev:4; metadata:created_at 2013_07_24, updated_at 2013_07_24;)
` 

Name : **WebShell ASPXShell - Title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-24

Last modified date : 2013-07-24

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018369
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WEBSHELL K-Shell/ZHC Shell 1.0/Aspx Shell Backdoor NetCat_Listener"; flow:established,from_server; file_data; content:"Silentz's Tricks:"; content:"action=cmd2"; content:"Start NC"; reference:url,www.fidelissecurity.com/webfm_send/377; reference:url,pastebin.com/XAG1Hnfd; classtype:web-application-attack; sid:2018369; rev:2; metadata:created_at 2014_04_07, updated_at 2014_04_07;)
` 

Name : **WEBSHELL K-Shell/ZHC Shell 1.0/Aspx Shell Backdoor NetCat_Listener** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.fidelissecurity.com/webfm_send/377|url,pastebin.com/XAG1Hnfd

CVE reference : Not defined

Creation date : 2014-04-07

Last modified date : 2014-04-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018371
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER ATTACKER WebShell - Zehir4.asp - content"; flow:established,from_server; file_data; content:"<title>zehir3--> powered by zehir"; content:"Sistem Bilgileri"; content:"color=red>Local Adres</td"; content:"zehirhacker"; reference:url,pastebin.com/m44e60e60; reference:url,www.fidelissecurity.com/webfm_send/377; classtype:web-application-attack; sid:2018371; rev:2; metadata:created_at 2014_04_07, updated_at 2014_04_07;)
` 

Name : **ATTACKER WebShell - Zehir4.asp - content** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,pastebin.com/m44e60e60|url,www.fidelissecurity.com/webfm_send/377

CVE reference : Not defined

Creation date : 2014-04-07

Last modified date : 2014-04-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018459
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SUSPICIOUS Possible WebShell Login Form (Outbound)"; flow:established,from_server; file_data; content:"<pre align=center><form method=post>Password|3a| <input type=password name=pass><input type=submit value=|27|>>|27|></form></pre>"; within:120; isdataat:!2,relative; metadata: former_category WEB_SERVER; reference:url,blog.malwaremustdie.org/2014/05/elf-shared-so-dynamic-library-malware.html; classtype:trojan-activity; sid:2018459; rev:2; metadata:created_at 2014_05_09, updated_at 2014_05_09;)
` 

Name : **SUSPICIOUS Possible WebShell Login Form (Outbound)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.malwaremustdie.org/2014/05/elf-shared-so-dynamic-library-malware.html

CVE reference : Not defined

Creation date : 2014-05-09

Last modified date : 2014-05-09

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018607
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Crawler"; flow:established,to_server; content:"PHPCrawl"; depth:8; http_user_agent; threshold:type limit, track by_src, count 1, seconds 300; reference:url,phpcrawl.cuab.de/; classtype:attempted-user; sid:2018607; rev:2; metadata:created_at 2014_06_25, updated_at 2014_06_25;)
` 

Name : **PHP Crawler** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,phpcrawl.cuab.de/

CVE reference : Not defined

Creation date : 2014-06-25

Last modified date : 2014-06-25

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018740
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Adobe Flash Player Rosetta Flash compressed CWS in URI"; flow:established,to_server; urilen:>70; content:"callback=CWS"; nocase; http_uri; content:"hC"; nocase; distance:5; within:2; http_uri; pcre:"/callback=CWS[a-z0-9\.\_]{5}hC[a-z0-9\.\_]{50}/Ui"; reference:url,miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/; reference:cve,2014-4671; classtype:attempted-user; sid:2018740; rev:2; metadata:created_at 2014_07_18, updated_at 2014_07_18;)
` 

Name : **Adobe Flash Player Rosetta Flash compressed CWS in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/|cve,2014-4671

CVE reference : Not defined

Creation date : 2014-07-18

Last modified date : 2014-07-18

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006445
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"FROM"; nocase; http_uri; pcre:"/SELECT\b.*FROM/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2006445; classtype:web-application-attack; sid:2006445; rev:13; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible SQL Injection Attempt SELECT FROM** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2006445

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 13

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009799
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SERVER PHP Attack Tool Morfeus F Scanner - M"; flow:established,to_server; content:"M Fucking Scanner"; http_user_agent; nocase; reference:url,www.webmasterworld.com/search_engine_spiders/3227720.htm; reference:url,doc.emergingthreats.net/2003466; classtype:web-application-attack; sid:2009799; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **PHP Attack Tool Morfeus F Scanner - M** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.webmasterworld.com/search_engine_spiders/3227720.htm|url,doc.emergingthreats.net/2003466

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010004
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL sp_start_job attempt"; flow:to_server,established; content:"sp_start_job"; http_uri; nocase; reference:url,doc.emergingthreats.net/2010004; classtype:attempted-user; sid:2010004; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **SQL sp_start_job attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010004

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010037
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection INTO OUTFILE Arbitrary File Write Attempt"; flow:established,to_server; content:"INTO"; http_uri; nocase; content:"OUTFILE"; nocase; http_uri; pcre:"/INTO.+OUTFILE/Ui"; reference:url,www.milw0rm.com/papers/372; reference:url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection; reference:url,websec.wordpress.com/2007/11/17/mysql-into-outfile/; reference:url,doc.emergingthreats.net/2010037; classtype:web-application-attack; sid:2010037; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible SQL Injection INTO OUTFILE Arbitrary File Write Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.milw0rm.com/papers/372|url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection|url,websec.wordpress.com/2007/11/17/mysql-into-outfile/|url,doc.emergingthreats.net/2010037

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010281
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Apache mod_perl Apache Status and Apache2 Status Cross Site Scripting Attempt"; flow:established,to_server; content:"|2F|APR|3A 3A|SockAddr|3A 3A|port|2F|"; http_uri; nocase; pcre:"/(script|img|src|alert|onmouse|onkey|onload|ondragdrop|onblur|onfocus|onclick)/Ui"; reference:url,www.securityfocus.com/bid/34383/info; reference:cve,2009-0796; reference:url,doc.emergingthreats.net/2010281; classtype:attempted-user; sid:2010281; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Apache mod_perl Apache Status and Apache2 Status Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : attempted-user

URL reference : url,www.securityfocus.com/bid/34383/info|cve,2009-0796|url,doc.emergingthreats.net/2010281

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010463
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER RFI Scanner Success (Fx29ID)"; flow:established,from_server; content:"FeeLCoMzFeeLCoMz"; reference:url,doc.emergingthreats.net/2010463; reference:url,opinion.josepino.com/php/howto_website_hack1; classtype:successful-user; sid:2010463; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **RFI Scanner Success (Fx29ID)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-user

URL reference : url,doc.emergingthreats.net/2010463|url,opinion.josepino.com/php/howto_website_hack1

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010621
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER SQL Injection Attempt (Agent CZ32ts)"; flow:to_server,established; content:"CZ32ts"; nocase; http_user_agent; reference:url,doc.emergingthreats.net/2009029; reference:url,www.Whitehatsecurityresponse.blogspot.com; classtype:web-application-attack; sid:2010621; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SQL Injection Attempt (Agent CZ32ts)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009029|url,www.Whitehatsecurityresponse.blogspot.com

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010667
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /bin/bash In URI, Possible Shell Command Execution Attempt Within Web Exploit"; flow:established,to_server; content:"/bin/bash"; http_uri; reference:url,doc.emergingthreats.net/2010667; classtype:web-application-attack; sid:2010667; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **/bin/bash In URI, Possible Shell Command Execution Attempt Within Web Exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010667

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010720
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Scan Precursor"; flow:established,to_server; content:"/thisdoesnotexistahaha.php"; http_uri; reference:url,doc.emergingthreats.net/2010720; classtype:web-application-attack; sid:2010720; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **PHP Scan Precursor** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010720

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011175
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Casper Bot Search RFI Scan"; flow:established,to_server; content:"Casper Bot"; nocase; http_user_agent; reference:url,doc.emergingthreats.net/2011175; classtype:web-application-attack; sid:2011175; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Casper Bot Search RFI Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2011175

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011759
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER TIEHTTP User-Agent"; flow:to_server,established; content:"User-Agent|3a| tiehttp"; nocase; reference:url,www.torry.net/authorsmore.php?id=4292; classtype:web-application-activity; sid:2011759; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TIEHTTP User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.torry.net/authorsmore.php?id=4292

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012116
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER DD-WRT Information Disclosure Attempt"; flow:established,to_server; content:"/Info.live.htm"; nocase; http_uri; flowbits:set,et.ddwrt.infodis; reference:url,www.exploit-db.com/exploits/15842/; classtype:attempted-recon; sid:2012116; rev:5; metadata:created_at 2010_12_30, updated_at 2010_12_30;)
` 

Name : **DD-WRT Information Disclosure Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.exploit-db.com/exploits/15842/

CVE reference : Not defined

Creation date : 2010-12-30

Last modified date : 2010-12-30

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012117
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Successful DD-WRT Information Disclosure"; flowbits:isset,et.ddwrt.infodis; flow:established,from_server; content:"lan_mac|3A 3A|"; content:"wlan_mac|3A 3A|"; distance:0; content:"lan_ip|3A 3A|"; distance:0; content:"mem_info|3A 3A|"; distance:0; reference:url,www.exploit-db.com/exploits/15842/; classtype:successful-recon-limited; sid:2012117; rev:3; metadata:created_at 2010_12_30, updated_at 2010_12_30;)
` 

Name : **Successful DD-WRT Information Disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,www.exploit-db.com/exploits/15842/

CVE reference : Not defined

Creation date : 2010-12-30

Last modified date : 2010-12-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012150
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP Large Subnormal Double Precision Floating Point Number PHP DoS in URI"; flow:established,to_server; content:"2.2250738585072011e-308"; http_uri; nocase; reference:url,bugs.php.net/bug.php?id=53632; classtype:attempted-dos; sid:2012150; rev:3; metadata:created_at 2011_01_06, updated_at 2011_01_06;)
` 

Name : **PHP Large Subnormal Double Precision Floating Point Number PHP DoS in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,bugs.php.net/bug.php?id=53632

CVE reference : Not defined

Creation date : 2011-01-06

Last modified date : 2011-01-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008207
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible File Injection Compromise (HaCKeD By BeLa & BodyguarD)"; flow:established,to_server; content:"HaCKeD By BeLa & BodyguarD"; reference:url,www.incidents.org/diary.html?storyid=4405; classtype:web-application-attack; sid:2008207; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible File Injection Compromise (HaCKeD By BeLa & BodyguarD)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.incidents.org/diary.html?storyid=4405

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015984
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Joomla Component SQLi Attempt"; flow:established,to_server; content:"option=com_"; http_uri; nocase; content:"union"; http_uri; nocase; distance:0; content:"select"; nocase; http_uri; distance:0; content:"from"; nocase; http_uri; distance:0; content:"jos_users"; distance:0; http_uri; nocase; fast_pattern; classtype:web-application-attack; sid:2015984; rev:3; metadata:created_at 2012_12_04, updated_at 2012_12_04;)
` 

Name : **Joomla Component SQLi Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-12-04

Last modified date : 2012-12-04

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016204
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby"; flow:established,to_server; content:" type"; nocase; fast_pattern; content:"yaml"; distance:0; nocase; content:"!ruby"; nocase; distance:0; pcre:"/<(?P<tname>[^\s]+)[^>]*?\stype\s*=\s*(?P<q>[\x22\x27])yaml(?P=q)((?!<\/(?P=tname)).+?)!ruby/si"; reference:url,groups.google.com/forum/?hl=en&fromgroups=#!topic/rubyonrails-security/61bkgvnSGTQ; classtype:web-application-attack; sid:2016204; rev:4; metadata:created_at 2013_01_11, updated_at 2013_01_11;)
` 

Name : **Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,groups.google.com/forum/?hl=en&fromgroups=#!topic/rubyonrails-security/61bkgvnSGTQ

CVE reference : Not defined

Creation date : 2013-01-11

Last modified date : 2013-01-11

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016305
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Ruby on Rails CVE-2013-0333 Attempt"; flow:established,to_server; pcre:"/^Content-Type\x3a[^\r\n]*(?:application\/json(?:request)?|text\/x-json)/Hmi"; content:"!ruby/"; http_client_body;  nocase; content:"NamedRouteCollection"; http_client_body; nocase; reference:url,gist.github.com/4660248; classtype:web-application-activity; sid:2016305; rev:7; metadata:created_at 2013_01_29, updated_at 2013_01_29;)
` 

Name : **Ruby on Rails CVE-2013-0333 Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,gist.github.com/4660248

CVE reference : Not defined

Creation date : 2013-01-29

Last modified date : 2013-01-29

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019244
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 1"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29|20|{|20|"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019244; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019245
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 2"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29|20|{%20"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019245; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019246
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 3"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29|20|%7b|20|"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019246; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019247
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 4"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29|20|%7b%20"; nocase; fast_pattern; within:13; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019247; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019248
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 5"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29%20{|20|"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019248; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 5** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019249
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 6"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29%20{%20"; nocase; fast_pattern; within:13; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019249; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 6** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019250
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 7"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29%20%7b|20|"; nocase; fast_pattern; within:13; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019250; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 7** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019251
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 8"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%29%20%7b%20"; nocase; fast_pattern; within:15; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019251; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 8** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019252
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 9"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28|20|{|20|"; nocase; fast_pattern; within:6; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019252; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 9** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019253
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 10"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28|20|{%20"; nocase; fast_pattern; within:8; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019253; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 10** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019254
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 11"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28|20|%7b|20|"; nocase; fast_pattern; within:8; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019254; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 11** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019255
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 12"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28|20|%7b%20"; nocase; fast_pattern; within:10; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019255; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 12** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019256
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 13"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%20{|20|"; nocase; fast_pattern; within:8; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019256; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 13** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019257
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 14"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%20{%20"; nocase; fast_pattern; within:10; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019257; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 14** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019258
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 15"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%20%7b|20|"; nocase; fast_pattern; within:10; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019258; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 15** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019259
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 16"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"%28%20%7b%20"; nocase; fast_pattern; within:12; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019259; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 16** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019260
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 17"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29|20|{|20|"; nocase; fast_pattern; within:7; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019260; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 17** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019261
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 18"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29|20|{%20"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019261; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 18** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019262
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 19"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29|20|%7b|20|"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019262; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 19** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019263
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 20"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29|20|%7b%20"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019263; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 20** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019264
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 21"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29%20{|20|"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019264; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 21** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019265
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 22"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29%20{%20"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019265; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 22** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019266
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 23"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29%20%7b|20|"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019266; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 23** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019267
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 24"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"(%29%20%7b%20"; nocase; fast_pattern; within:13; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019267; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 24** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019269
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 26"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()|20|%7b|20|"; nocase; fast_pattern; within:7; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019269; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 26** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019270
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 27"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()|20|%7b%20"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019270; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 27** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019271
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 28"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()%20{|20|"; nocase; fast_pattern; within:7; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019271; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 28** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019272
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 29"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()%20%7b|20|"; nocase; fast_pattern; within:9; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019272; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 29** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019273
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 30"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()%20%7b%20"; nocase; fast_pattern; within:11; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019273; rev:3; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 30** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019268
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 25"; flow:established,to_server; pcre:"/[\?\=\x3a\s\x2f]/"; content:"()|20|{%20"; nocase; fast_pattern; within:7; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019268; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP URLENCODE Generic 25** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019239
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie"; flow:established,to_server; content:"|28 29 20 7b|"; http_cookie; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019239; rev:4; metadata:created_at 2014_09_25, updated_at 2014_09_25;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP Cookie** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2014-09-25

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019526
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WEB-PHP phpinfo access"; flow:to_server,established; content:"/phpinfo.php"; http_uri; nocase; reference:bugtraq,5789; reference:cve,2002-1149; reference:url,www.osvdb.org/displayvuln.php?osvdb_id=3356; classtype:successful-recon-limited; sid:2019526; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **WEB-PHP phpinfo access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : bugtraq,5789|cve,2002-1149|url,www.osvdb.org/displayvuln.php?osvdb_id=3356

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100139
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER WEB-IIS Remote IIS Server Name spoof attempt loopback IP"; flow:to_server,established; content:"http|3a|//127.0.0.1"; pcre:"/http\x3A\/\/127\.0\.0\.1\/.*\.asp/i"; reference:cve,2005-2678; classtype:web-application-activity; sid:2100139; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **WEB-IIS Remote IIS Server Name spoof attempt loopback IP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : cve,2005-2678

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101877
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL WEB_SERVER printenv access"; flow:to_server,established; content:"/printenv"; http_uri; reference:bugtraq,1658; reference:cve,2000-0868; reference:nessus,10188; reference:nessus,10503; classtype:web-application-activity; sid:2101877; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **printenv access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : bugtraq,1658|cve,2000-0868|nessus,10188|nessus,10503

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018495
`alert http $EXTERNAL_NET any -> $HOME_NET [9200,9292] (msg:"ET WEB_SERVER Possible CVE-2014-3120 Elastic Search Remote Code Execution Attempt"; flow:established,to_server; content:"search"; http_uri; nocase; content:"source="; nocase; distance:0; http_uri; content:"script_fields"; http_uri; nocase; distance:0; content:"import"; distance:0; http_uri; nocase; content:"java."; http_uri; nocase; distance:0; reference:url,bouk.co/blog/elasticsearch-rce/; classtype:attempted-admin; sid:2018495; rev:3; metadata:created_at 2014_05_21, updated_at 2014_05_21;)
` 

Name : **Possible CVE-2014-3120 Elastic Search Remote Code Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,bouk.co/blog/elasticsearch-rce/

CVE reference : Not defined

Creation date : 2014-05-21

Last modified date : 2014-05-21

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019804
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP.//Input in HTTP POST"; flow:established,to_server; content:"POST"; http_method; content:"php|3a 2f 2f|input"; http_raw_uri; fast_pattern; content:"<?"; http_client_body; depth:2; reference:url,www.deependresearch.org/2014/07/another-linux-ddos-bot-via-cve-2012-1823.html; classtype:trojan-activity; sid:2019804; rev:3; metadata:created_at 2014_11_25, updated_at 2014_11_25;)
` 

Name : **PHP.//Input in HTTP POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.deependresearch.org/2014/07/another-linux-ddos-bot-via-cve-2012-1823.html

CVE reference : Not defined

Creation date : 2014-11-25

Last modified date : 2014-11-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019880
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Double Encoded Characters in URI (../)"; flow:to_server,established; content:"%252E%252E%252F"; nocase; http_raw_uri; classtype:misc-attack; sid:2019880; rev:4; metadata:created_at 2014_12_05, updated_at 2014_12_05;)
` 

Name : **Double Encoded Characters in URI (../)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-05

Last modified date : 2014-12-05

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019899
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Insomnia Shell HTTP Request"; flow:to_server,established; content:"POST"; http_method; content:".aspx"; http_uri; content:"txtRemoteHost="; http_client_body; fast_pattern; content:"txtRemotePort="; http_client_body; distance:0; content:"txtBindPort="; http_client_body; distance:0; content:"txtPipeName="; http_client_body; distance:0; reference:url,www.insomniasec.com/releases; classtype:trojan-activity; sid:2019899; rev:2; metadata:created_at 2014_12_09, updated_at 2014_12_09;)
` 

Name : **Insomnia Shell HTTP Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.insomniasec.com/releases

CVE reference : Not defined

Creation date : 2014-12-09

Last modified date : 2014-12-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019900
`alert tcp $HOME_NET !21:23 -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Insomnia Shell Outbound CMD Banner"; flow:to_server,established; content:"Shell enroute......."; depth:20; content:"Microsoft Windows "; content:"Copyright |28|c|29| 20"; distance:0; content:"Microsoft Corp"; distance:0; reference:url,www.insomniasec.com/releases; classtype:trojan-activity; sid:2019900; rev:1; metadata:created_at 2014_12_09, updated_at 2014_12_09;)
` 

Name : **Insomnia Shell Outbound CMD Banner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.insomniasec.com/releases

CVE reference : Not defined

Creation date : 2014-12-09

Last modified date : 2014-12-09

Rev version : 1

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013939
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (shell_exec() function used)"; flow:to_server,established; content:"aGVsbF9l"; http_header;  reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013939; rev:4; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (shell_exec() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013940
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (proc_open() function used)"; flow:to_server,established; content:"JHAgPSBhcnJheShhcnJh"; http_header;  reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013940; rev:4; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (proc_open() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013941
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (popen() function used)"; flow:to_server,established; content:"JGggPSBwb3Bl"; http_header;  reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013941; rev:4; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (popen() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013944
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (perl->system() function used)"; flow:to_server,established; content:"JHBlcmwgPSBuZXcg"; http_header;  reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013944; rev:4; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (perl->system() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013945
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (exec() function used)"; flow:to_server,established; content:"ZXhlYygn"; http_header;  reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013945; rev:4; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (exec() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013937
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (system() function used)"; flow:to_server,established; content:"QHN5c3Rl"; http_header; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013937; rev:6; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (system() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020097
`alert http any any -> any any (msg:"ET WEB_SERVER ATTACKER WebShell - 1337w0rm - cPanel Cracker"; flow:established,to_server; content:"user=CRACKER"; http_client_body; classtype:trojan-activity; sid:2020097; rev:2; metadata:created_at 2015_01_06, updated_at 2015_01_06;)
` 

Name : **ATTACKER WebShell - 1337w0rm - cPanel Cracker** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-06

Last modified date : 2015-01-06

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020096
`alert http any any -> any any (msg:"ET WEB_SERVER ATTACKER WebShell - 1337w0rm - Landing Page"; flow:established,to_client; file_data; content:"cPanel Cracker"; classtype:trojan-activity; sid:2020096; rev:3; metadata:created_at 2015_01_06, updated_at 2015_01_06;)
` 

Name : **ATTACKER WebShell - 1337w0rm - Landing Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-06

Last modified date : 2015-01-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020102
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP System Command in HTTP POST"; flow:established,to_server; content:"POST"; http_method; content:"<?"; http_client_body; content:"system|28|"; http_client_body; distance:0; classtype:web-application-attack; sid:2020102; rev:4; metadata:created_at 2015_01_06, updated_at 2015_01_06;)
` 

Name : **PHP System Command in HTTP POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-06

Last modified date : 2015-01-06

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020338
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WPScan User Agent"; flow:established,to_server; content:"WPScan v"; depth:8; http_user_agent; threshold: type limit, count 1, seconds 60, track by_src; reference:url,github.com/wpscanteam/wpscan; classtype:web-application-attack; sid:2020338; rev:3; metadata:created_at 2015_01_30, updated_at 2015_01_30;)
` 

Name : **WPScan User Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,github.com/wpscanteam/wpscan

CVE reference : Not defined

Creation date : 2015-01-30

Last modified date : 2015-01-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020555
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ATTACKER WebShell - Weevely - Downloaded"; flow:established,to_client; file_data; content:"<?php|0A|$"; content:"="; distance:4; within:2; content:" str_replace("; distance:0; classtype:trojan-activity; sid:2020555; rev:2; metadata:created_at 2015_02_24, updated_at 2015_02_24;)
` 

Name : **ATTACKER WebShell - Weevely - Downloaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2015-02-24

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020556
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ATTACKER WebShell - Weevely - POSTed"; flow:established,to_server; content:"<?php|0A|$"; http_client_body; content:"="; distance:4; within:2; http_client_body; content:" str_replace("; distance:0; http_client_body; classtype:trojan-activity; sid:2020556; rev:2; metadata:created_at 2015_02_24, updated_at 2015_02_24;)
` 

Name : **ATTACKER WebShell - Weevely - POSTed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2015-02-24

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020557
`alert http any any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER ATTACKER WebShell - Weevely - Cookie"; flow:established,to_server; content:"ing|3a| identity|0D 0A|Host|3a|"; http_header; content:"SESS="; http_cookie; content:"|3B| SID="; distance:0; http_cookie; content:"|3B| PREF="; distance:0; http_cookie; content:"|3B|SSID="; distance:0; http_cookie; classtype:trojan-activity; sid:2020557; rev:2; metadata:created_at 2015_02_24, updated_at 2015_02_24;)
` 

Name : **ATTACKER WebShell - Weevely - Cookie** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2015-02-24

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020572
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - ASPyder - File Create - POST Structure"; flow:established,to_server; content:"POST"; http_method; content:"Fname="; http_client_body; depth:6; content:"&cmd="; http_client_body; classtype:trojan-activity; sid:2020572; rev:3; metadata:created_at 2015_02_25, updated_at 2015_02_25;)
` 

Name : **WebShell - ASPyder - File Create - POST Structure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-25

Last modified date : 2015-02-25

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010920
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=)"; flow:to_server,established; content:"GET"; nocase; http_method; content:".php?"; nocase; http_uri; content:"cmd="; http_uri; fast_pattern; nocase; pcre:"/[&?]cmd=[^\x26\x28]*(?:cd|\;|echo|cat|perl|curl|wget|id|uname|t?ftp)/Ui"; reference:cve,2002-0953; reference:url,doc.emergingthreats.net/2010920; classtype:web-application-attack; sid:2010920; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Exploit Suspected PHP Injection Attack (cmd=)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2002-0953|url,doc.emergingthreats.net/2010920

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020648
`alert tcp $EXTERNAL_NET any -> $HOME_NET [9200,9292] (msg:"ET WEB_SERVER Possible CVE-2015-1427 Elastic Search Sandbox Escape Remote Code Execution Attempt"; flow:established,to_server; content:"POST /"; depth:6; content:"search"; distance:0; content:"script_fields"; distance:0; nocase; content:".class.forName"; nocase; distance:0; content:"java.lang.Runtime"; nocase; distance:0; reference:url,jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427; classtype:attempted-admin; sid:2020648; rev:2; metadata:created_at 2015_03_09, updated_at 2015_03_09;)
` 

Name : **Possible CVE-2015-1427 Elastic Search Sandbox Escape Remote Code Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427

CVE reference : Not defined

Creation date : 2015-03-09

Last modified date : 2015-03-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2021138
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER ElasticSearch Directory Traversal Attempt (CVE-2015-3337)"; flow:to_server,established; content:"/_plugin/"; http_raw_uri; fast_pattern; pcre:"/(?:%2(?:52e(?:%2(?:52e(?:%(?:(?:25)?2|c0%a)f|\/)|e(?:%(?:(?:25)?2|c0%a)f|\/))|\.(?:%(?:(?:25)?2|c0%a)f|\/))|e(?:%2(?:52e(?:%(?:(?:25)?2|c0%a)f|\/)|e(?:%(?:(?:25)?2|c0%a)f|\/))|\.(?:%(?:(?:25)?2|c0%a)f|\/)))|\.(?:%2(?:52e(?:%(?:(?:25)?2|c0%a)f|\/)|e(?:%(?:(?:25)?2|c0%a)f|\/))|\.(?:%(?:(?:25)?2|c0%a)f|\/)))/RIi"; reference:cve,2015-3337; classtype:web-application-attack; sid:2021138; rev:4; metadata:created_at 2015_05_22, updated_at 2015_05_22;)
` 

Name : **ElasticSearch Directory Traversal Attempt (CVE-2015-3337)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2015-3337

CVE reference : Not defined

Creation date : 2015-05-22

Last modified date : 2015-05-22

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016680
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - net user"; flow:established,to_server; content:"POST"; http_method; content:"net"; nocase; http_client_body; content:!"work"; within:4; nocase; http_client_body; content:"user"; nocase; within:11; http_client_body; content:!"-agent"; nocase; http_client_body; within:6; pcre:"/net(?:%(?:25)?20|\s)+user/Pi"; classtype:bad-unknown; sid:2016680; rev:6; metadata:created_at 2013_03_27, updated_at 2013_03_27;)
` 

Name : **WebShell Generic - net user** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2013-03-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002777
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Light Weight Calendar 'date' Arbitrary Remote Code Execution"; flow: to_server,established; content:"/index.php?"; nocase; http_uri; content:"date="; fast_pattern; http_uri; pcre:"/date=\d{8}\)\;./Ui"; reference:url,doc.emergingthreats.net/2002777; classtype:web-application-attack; sid:2002777; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Light Weight Calendar 'date' Arbitrary Remote Code Execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2002777

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017389
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - ASPyder - Auth Creds"; flow:established,to_server; content:!"&date="; http_client_body; content:"code="; http_client_body; depth:5; content:"&submit="; distance:0; http_client_body; classtype:trojan-activity; sid:2017389; rev:6; metadata:created_at 2013_08_28, updated_at 2013_08_28;)
` 

Name : **WebShell - ASPyder - Auth Creds** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-28

Last modified date : 2013-08-28

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022485
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Possible Compromised Webserver Retriving Inject"; flow:established,to_server; content:"/blog/?"; depth:7; http_uri; pcre:"/^\/blog\/\?[a-z]+&utm_source=\d+\x3a\d+\x3a\d+$/U"; pcre:"/^Host\x3a\x20(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\x3a\d{1,5})?\r?\n/Hmi"; classtype:trojan-activity; sid:2022485; rev:2; metadata:created_at 2016_02_03, updated_at 2016_02_03;)
` 

Name : **Possible Compromised Webserver Retriving Inject** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-02-03

Last modified date : 2016-02-03

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017174
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirect"; flow:established,to_server; content:"redirect|3a|"; http_client_body; content:"{"; http_client_body; distance:0; pcre:"/\bredirect\x3a/P"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017174; rev:5; metadata:created_at 2013_07_23, updated_at 2013_07_23;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-23

Last modified date : 2013-07-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017175
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirectAction"; flow:established,to_server; content:"redirectAction|3a|"; http_client_body; content:"{"; http_client_body; pcre:"/\bredirectAction\x3a/P"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017175; rev:5; metadata:created_at 2013_07_23, updated_at 2013_07_23;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 redirectAction** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-23

Last modified date : 2013-07-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017176
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Command Execution CVE-2013-2251 action"; flow:established,to_server; content:"action|3a|"; http_client_body; content:"{"; http_client_body; distance:0; pcre:"/\baction\x3a/P"; reference:url,struts.apache.org/release/2.3.x/docs/s2-016.html; classtype:attempted-user; sid:2017176; rev:5; metadata:created_at 2013_07_23, updated_at 2013_07_23;)
` 

Name : **Possible Apache Struts OGNL Command Execution CVE-2013-2251 action** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,struts.apache.org/release/2.3.x/docs/s2-016.html

CVE reference : Not defined

Creation date : 2013-07-23

Last modified date : 2013-07-23

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022596
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Custom Content Type Manager WP Backdoor Access"; flow:established,to_server; content:"/plugins/custom-content-type-manager/auto-update.php"; http_uri; fast_pattern:32,20; nocase; reference:url,blog.sucuri.net/2016/03/when-wordpress-plugin-goes-bad.html; classtype:trojan-activity; sid:2022596; rev:3; metadata:created_at 2016_03_06, updated_at 2016_03_06;)
` 

Name : **Possible Custom Content Type Manager WP Backdoor Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.sucuri.net/2016/03/when-wordpress-plugin-goes-bad.html

CVE reference : Not defined

Creation date : 2016-03-06

Last modified date : 2016-03-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022846
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2016-5118 Exploit SVG attempt M1"; flow:established,to_server; content:"<svg"; nocase; http_client_body; content:"|78 6c 69 6e 6b 3a 68 72 65 66 3d 22 7c|"; http_client_body; reference:url,seclists.org/oss-sec/2016/q2/432; reference:cve,2016-5118; classtype:trojan-activity; sid:2022846; rev:2; metadata:created_at 2016_06_01, updated_at 2016_06_01;)
` 

Name : **Possible CVE-2016-5118 Exploit SVG attempt M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/oss-sec/2016/q2/432|cve,2016-5118

CVE reference : Not defined

Creation date : 2016-06-01

Last modified date : 2016-06-01

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022847
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2016-5118 Exploit SVG attempt M2"; flow:established,to_server; content:"<svg"; nocase; http_client_body; content:"|78 6c 69 6e 6b 3a 68 72 65 66 3d 27 7c|"; http_client_body; nocase; reference:url,seclists.org/oss-sec/2016/q2/432; reference:cve,2016-5118; classtype:trojan-activity; sid:2022847; rev:2; metadata:created_at 2016_06_01, updated_at 2016_06_01;)
` 

Name : **Possible CVE-2016-5118 Exploit SVG attempt M2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/oss-sec/2016/q2/432|cve,2016-5118

CVE reference : Not defined

Creation date : 2016-06-01

Last modified date : 2016-06-01

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010794
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER DFind w00tw00t GET-Requests"; flow:established,to_server; content:"GET"; nocase; http_method; content:"/w00tw00t."; nocase; http_uri; depth:10; reference:url,doc.emergingthreats.net/2010794; classtype:attempted-recon; sid:2010794; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **DFind w00tw00t GET-Requests** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2010794

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023143
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER AnonGhost PHP Webshell"; flow:from_server,established; file_data; content:"base64_decode("; content:"Bbm9uR2hvc3Qg"; fast_pattern; classtype:trojan-activity; sid:2023143; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2016_09_01, performance_impact Low, updated_at 2016_09_01;)
` 

Name : **AnonGhost PHP Webshell** 

Attack target : Web_Server

Description : Alert is generated when a webshell containing this group's signature is uploaded or potentially accessed (if the PHP interpreter is broken).

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-09-01

Last modified date : 2016-09-01

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2023535
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL Expression Injection"; flow:to_server,established; content:"|24 7b|"; http_uri; content:"|25 7b|"; distance:0; http_uri; content:"|7d|"; distance:0; http_uri; pcre:"/\${\s*?%{/U"; reference:cve,2013-2135; reference:bugtraq,60345; reference:url,cwiki.apache.org/confluence/display/WW/S2-015; classtype:web-application-attack; sid:2023535; rev:2; metadata:affected_product Apache_HTTP_server, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2016_11_18, performance_impact Low, updated_at 2016_11_18;)
` 

Name : **Possible Apache Struts OGNL Expression Injection** 

Attack target : Web_Server

Description : This signature will match on an attempt to exploit the Apache Struts remote OGNL expression injection vulnerability. 

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : web-application-attack

URL reference : cve,2013-2135|bugtraq,60345|url,cwiki.apache.org/confluence/display/WW/S2-015

CVE reference : Not defined

Creation date : 2016-11-18

Last modified date : 2016-11-18

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2016935
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL Injection Select Sleep Time Delay"; flow:established,to_server; content:"SELECT"; http_uri; nocase; content:"SLEEP|28|"; http_uri; nocase; distance:0; pcre:"/\bSELECT.*?\bSLEEP\x28/Ui"; reference:url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet; classtype:web-application-attack; sid:2016935; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2013_05_28, updated_at 2016_07_01;)
` 

Name : **SQL Injection Select Sleep Time Delay** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

CVE reference : Not defined

Creation date : 2013-05-28

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017640
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Encrypted Webshell Download"; flow:established,to_client; file_data; content:"eval"; content:"mcrypt_decrypt"; distance:0; within:30; reference:url,blog.sucuri.net/2013/10/backdoor-evasion-using-encrypted-content.html; classtype:bad-unknown; sid:2017640; rev:3; metadata:affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2013_10_28, performance_impact Low, updated_at 2017_01_23;)
` 

Name : **Possible Encrypted Webshell Download** 

Attack target : Web_Server

Description : This signature matches on an attempt to obfuscate CnC commands issued to a backdoor that runs on web server by making use of mcrypt_decrypt function.

Tags : Not defined

Affected products : PHP

Alert Classtype : bad-unknown

URL reference : url,blog.sucuri.net/2013/10/backdoor-evasion-using-encrypted-content.html

CVE reference : Not defined

Creation date : 2013-10-28

Last modified date : 2017-01-23

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2013943
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (pcntl_exec() function used)"; flow:to_server,established; content:"JGFyZ3MgPSBh"; http_header; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013943; rev:6; metadata:created_at 2011_11_21, updated_at 2011_11_21;)
` 

Name : **Weevely PHP backdoor detected (pcntl_exec() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2011-11-21

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013942
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (python_eval() function used)"; flow:to_server,established; content:"QHB5dGhvbl9l"; http_header; metadata: former_category WEB_SERVER; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013942; rev:5; metadata:created_at 2011_11_21, updated_at 2017_03_21;)
` 

Name : **Weevely PHP backdoor detected (python_eval() function used)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2017-03-21

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024107
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Microsoft IIS Remote Code Execution (CVE-2017-7269)"; flow:to_server,established; content:"If|3a 20 3c|"; http_header; pcre:"/^If\x3a\x20\x3c[^\r\n>]+?(?:[\x7f-\xff])/Hmi"; metadata: former_category WEB_SERVER; reference:url,github.com/edwardz246003/IIS_exploit/blob/master/exploit.py; classtype:attempted-user; sid:2024107; rev:2; metadata:affected_product Microsoft_IIS, attack_target Web_Server, deployment Datacenter, cve cve_2017_7269, signature_severity Major, created_at 2017_03_28, performance_impact Low, updated_at 2017_03_28;)
` 

Name : **Microsoft IIS Remote Code Execution (CVE-2017-7269)** 

Attack target : Web_Server

Description : This signature matches an attack against Internet Information Services (IIS) buffer overflow vulnerability in the ScStoragePathFromUrl function in the WebDAV service resulting in remote code execution.

Tags : Not defined

Affected products : Microsoft_IIS

Alert Classtype : attempted-user

URL reference : url,github.com/edwardz246003/IIS_exploit/blob/master/exploit.py

CVE reference : cve,2017-7269

Creation date : 2017-03-28

Last modified date : 2017-03-28

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2011243
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (ByroeNet/Casper-Like planetwork)"; flow:established,to_server; content:"plaNETWORK Bot"; nocase; http_user_agent; metadata: former_category WEB_SERVER; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; reference:url,doc.emergingthreats.net/2011243; classtype:web-application-attack; sid:2011243; rev:7; metadata:created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Bot Search RFI Scan (ByroeNet/Casper-Like planetwork)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/|url,doc.emergingthreats.net/2011243

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017528
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER UA WordPress probable DDOS-Attack"; flow:established,to_server; content:"Wordpress/"; http_user_agent; depth:10; metadata: former_category WEB_SERVER; reference:url,thehackernews.com/2013/09/thousands-of-wordpress-blogs.html; reference:url,pastebin.com/NP64hTQr; classtype:bad-unknown; sid:2017528; rev:5; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2013_09_30, updated_at 2017_05_11;)
` 

Name : **UA WordPress probable DDOS-Attack** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : bad-unknown

URL reference : url,thehackernews.com/2013/09/thousands-of-wordpress-blogs.html|url,pastebin.com/NP64hTQr

CVE reference : Not defined

Creation date : 2013-09-30

Last modified date : 2017-05-11

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024760
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER OptionsBleed (CVE-2017-9798)"; flow:from_server; content:"Allow|3a 20|"; http_header; pcre:"/^[^\n]+(?:[^ -~\x0d\x0a]|,\x20*,)/HR"; metadata: former_category WEB_SERVER; reference:cve,CVE-2017-9798; classtype:misc-activity; sid:2024760; rev:4; metadata:affected_product Apache_HTTP_server, attack_target Server, deployment Datacenter, signature_severity Minor, created_at 2017_09_19, performance_impact Significant, updated_at 2017_09_22;)
` 

Name : **OptionsBleed (CVE-2017-9798)** 

Attack target : Server

Description : alerts on non legal characters in Allow header indicating data from leaked memory in response

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : misc-activity

URL reference : cve,CVE-2017-9798

CVE reference : Not defined

Creation date : 2017-09-19

Last modified date : 2017-09-22

Rev version : 4

Category : WEB_SERVER

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Significant

# 2024930
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER 401TRG Generic Webshell Request - POST with wget in body"; flow:established,to_server; content:"wget"; nocase; http_client_body; content:"http"; nocase; http_client_body; within:11; threshold:type limit, track by_src, seconds 3600, count 1; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2024930; rev:1; metadata:affected_product Apache_HTTP_server, attack_target Server, deployment Datacenter, signature_severity Major, created_at 2017_10_26, malware_family webshell, performance_impact Moderate, updated_at 2017_10_26;)
` 

Name : **401TRG Generic Webshell Request - POST with wget in body** 

Attack target : Server

Description : Alerts on generic webshell type request

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-10-26

Last modified date : 2017-10-26

Rev version : 1

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : webshell

Type : SID

Performance Impact : Moderate

# 2010515
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Possible HTTP 403 XSS Attempt (Local Source)"; flow:from_server,established; content:"403"; http_stat_code; file_data; content:"<script"; nocase; depth:512; content:!"location.replace|28 22|https|3a 2f 2f|block.opendns.com"; distance:0; reference:url,doc.emergingthreats.net/2010515; classtype:web-application-attack; sid:2010515; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible HTTP 403 XSS Attempt (Local Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010515

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2024265
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Jorgee Scan"; flow:established,to_server; content:"HEAD"; http_method; content:"Mozilla/5.0 Jorgee"; depth:18; isdataat:!1,relative; http_user_agent; fast_pattern; threshold: type limit, track by_dst, count 3, seconds 60; metadata: former_category WEB_SERVER; reference:url,www.skepticism.us/2015/05/new-malware-user-agent-value-jorgee/; classtype:trojan-activity; sid:2024265; rev:4; metadata:created_at 2015_06_26, updated_at 2019_09_28;)
` 

Name : **Jorgee Scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.skepticism.us/2015/05/new-malware-user-agent-value-jorgee/

CVE reference : Not defined

Creation date : 2015-06-26

Last modified date : 2019-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010963
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SELECT USER SQL Injection Attempt in URI"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"USER"; nocase; http_uri; pcre:"/SELECT[^a-z]+USER/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2010963; classtype:web-application-attack; sid:2010963; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **SELECT USER SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2010963

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009714
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt"; flow:to_server,established; content:"</script>"; nocase; http_uri; metadata: former_category WEB_SERVER; reference:url,ha.ckers.org/xss.html; reference:url,doc.emergingthreats.net/2009714; classtype:web-application-attack; sid:2009714; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2017_05_11;)
` 

Name : **Script tag in URI Possible Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,ha.ckers.org/xss.html|url,doc.emergingthreats.net/2009714

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-05-11

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022816
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQLi Attempt in User Agent (Inbound)"; flow:established,to_server; content:"select"; nocase; distance:0; fast_pattern; http_user_agent; content:"from"; nocase; http_user_agent; within:20; reference:url,blog.cloudflare.com/the-sleepy-user-agent/; classtype:trojan-activity; sid:2022816; rev:3; metadata:created_at 2016_05_17, updated_at 2016_05_17;)
` 

Name : **Possible SQLi Attempt in User Agent (Inbound)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.cloudflare.com/the-sleepy-user-agent/

CVE reference : Not defined

Creation date : 2016-05-17

Last modified date : 2016-05-17

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011037
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"VERSION"; nocase; distance:1; http_uri; reference:url,support.microsoft.com/kb/321185; reference:url,doc.emergingthreats.net/2011037; classtype:web-application-attack; sid:2011037; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Attempt to Get SQL Server Version in URI using SELECT VERSION** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,support.microsoft.com/kb/321185|url,doc.emergingthreats.net/2011037

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010592
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Microsoft Internet Information Services (IIS) .asp Filename Extension Parsing File Upload Security Bypass Attempt (asp)"; flow:established,to_server; content:".asp|3B 2E|"; nocase; http_uri; reference:url,www.securityfocus.com/bid/37460/info; reference:url,doc.emergingthreats.net/2010592; reference:url,www.securityfocus.com/bid/37460/info; reference:url,soroush.secproject.com/downloadable/iis-semicolon-report.pdf; reference:cve,2009-4444; classtype:web-application-attack; sid:2010592; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Microsoft Internet Information Services (IIS) .asp Filename Extension Parsing File Upload Security Bypass Attempt (asp)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/37460/info|url,doc.emergingthreats.net/2010592|url,www.securityfocus.com/bid/37460/info|url,soroush.secproject.com/downloadable/iis-semicolon-report.pdf|cve,2009-4444

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011141
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Easteregg Information-Disclosure (phpinfo)"; flow:to_server,established; content:"?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"; http_uri; reference:url,osvdb.org/12184; reference:url,www.0php.com/php_easter_egg.php; reference:url,seclists.org/nmap-dev/2010/q2/569; reference:url,doc.emergingthreats.net/2011141; classtype:attempted-recon; sid:2011141; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **PHP Easteregg Information-Disclosure (phpinfo)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,osvdb.org/12184|url,www.0php.com/php_easter_egg.php|url,seclists.org/nmap-dev/2010/q2/569|url,doc.emergingthreats.net/2011141

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009362
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /system32/ in Uri - Possible Protected Directory Access Attempt"; flow:established,to_server; content:"/system32/"; nocase; http_uri; reference:url,doc.emergingthreats.net/2009362; classtype:attempted-recon; sid:2009362; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **/system32/ in Uri - Possible Protected Directory Access Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009362

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017134
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WebShell - Generic - GIF Header With HTML Form"; flow:established,to_client; file_data; content:"GIF89a"; within:6; content:"<form "; nocase; fast_pattern; within:150; content:!"_VIEWSTATE"; classtype:trojan-activity; sid:2017134; rev:5; metadata:created_at 2013_07_11, updated_at 2013_07_11;)
` 

Name : **WebShell - Generic - GIF Header With HTML Form** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-11

Last modified date : 2013-07-11

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013938
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (passthru() function used) M1"; flow:to_server,established; content:"QHBhc3N0aHJ1KC"; http_header;  metadata: former_category WEB_SERVER; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2013938; rev:5; metadata:created_at 2011_11_21, updated_at 2018_06_14;)
` 

Name : **Weevely PHP backdoor detected (passthru() function used) M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2011-11-21

Last modified date : 2018-06-14

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2025593
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (passthru() function used) M2"; flow:to_server,established; content:"BwYXNzdGhydSgn"; http_header; metadata: former_category WEB_SERVER; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2025593; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2018_06_14, malware_family weevely, updated_at 2018_06_14;)
` 

Name : **Weevely PHP backdoor detected (passthru() function used) M2** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2018-06-14

Last modified date : 2018-06-14

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : weevely

Type : SID

Performance Impact : Not defined

# 2025594
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Weevely PHP backdoor detected (passthru() function used) M3"; flow:to_server,established; content:"AcGFzc3RocnUoJ"; http_header; metadata: former_category WEB_SERVER; reference:url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar; classtype:web-application-activity; sid:2025594; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2018_06_14, malware_family weevely, updated_at 2018_06_14;)
` 

Name : **Weevely PHP backdoor detected (passthru() function used) M3** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-activity

URL reference : url,bechtsoudis.com/security/put-weevely-on-the-your-nids-radar

CVE reference : Not defined

Creation date : 2018-06-14

Last modified date : 2018-06-14

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : weevely

Type : SID

Performance Impact : Not defined

# 2026337
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER JSP.SJavaWebManage WebShell Pass 20-09-2018 1"; flow:established,from_server; file_data; content:"|3c 25 40|page"; depth:7; content:"String|20|PASS|20|=|20 22|09a0aa1091460d23e5a68550826b359b|22|"; distance:0; fast_pattern; metadata: former_category WEB_SERVER; reference:md5,91eaca79943c972cb2ca7ee0e462922c; classtype:trojan-activity; sid:2026337; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag WebShell, signature_severity Major, created_at 2018_09_20, malware_family SJavaWebManage, performance_impact Low, updated_at 2018_09_25;)
` 

Name : **JSP.SJavaWebManage WebShell Pass 20-09-2018 1** 

Attack target : Web_Server

Description : Not defined

Tags : WebShell

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : md5,91eaca79943c972cb2ca7ee0e462922c

CVE reference : Not defined

Creation date : 2018-09-20

Last modified date : 2018-09-25

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : SJavaWebManage

Type : SID

Performance Impact : Low

# 2026338
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER JSP.SJavaWebManage WebShell Pass 20-09-2018 2"; flow:established,from_server; file_data; content:"|3c 25 40|page"; depth:7; content:"String|20|PASS|20|=|20 22|098f6bcd4621d373cade4e832627b4f6|22|"; distance:0; fast_pattern; metadata: former_category WEB_SERVER; reference:md5,91eaca79943c972cb2ca7ee0e462922c; classtype:trojan-activity; sid:2026338; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag WebShell, signature_severity Major, created_at 2018_09_20, malware_family SJavaWebManage, performance_impact Low, updated_at 2018_09_25;)
` 

Name : **JSP.SJavaWebManage WebShell Pass 20-09-2018 2** 

Attack target : Web_Server

Description : Not defined

Tags : WebShell

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : md5,91eaca79943c972cb2ca7ee0e462922c

CVE reference : Not defined

Creation date : 2018-09-20

Last modified date : 2018-09-25

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : SJavaWebManage

Type : SID

Performance Impact : Low

# 2026336
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER JSP.SJavaWebManage WebShell Access"; flow:established,from_server; file_data; content:"|3c 25 40|page"; depth:7; content:"|22|os.name|22|"; distance:0; content:"|22|/bin/sh|22|"; distance:0; content:"getRuntime|28 29|.exec|28|"; fast_pattern; metadata: former_category WEB_SERVER; reference:md5,91eaca79943c972cb2ca7ee0e462922c; classtype:trojan-activity; sid:2026336; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag WebShell, signature_severity Major, created_at 2018_09_20, malware_family SJavaWebManage, performance_impact Low, updated_at 2018_09_25;)
` 

Name : **JSP.SJavaWebManage WebShell Access** 

Attack target : Web_Server

Description : Not defined

Tags : WebShell

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : md5,91eaca79943c972cb2ca7ee0e462922c

CVE reference : Not defined

Creation date : 2018-09-20

Last modified date : 2018-09-25

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : SJavaWebManage

Type : SID

Performance Impact : Low

# 2019627
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Cookie Based BackDoor Used in Drupal Attacks"; flow:established,to_server; content:"preg_replace"; http_cookie; nocase; metadata: former_category WEB_SERVER; reference:url,www.kahusecurity.com/posts/drupal_7_sql_injection_info.html; classtype:attempted-user; sid:2019627; rev:3; metadata:created_at 2014_11_03, updated_at 2014_11_03;)
` 

Name : **Possible Cookie Based BackDoor Used in Drupal Attacks** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.kahusecurity.com/posts/drupal_7_sql_injection_info.html

CVE reference : Not defined

Creation date : 2014-11-03

Last modified date : 2014-11-03

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026719
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HP Intelligent Management Java Deserialization RCE Attempt"; flow:established,to_server; content:"POST"; http_method; content:"/login.jsf"; http_uri; content:"java.util.HashMap"; http_client_body; content:"javax.management.openmbean.TabularDataSupport"; http_client_body; metadata: former_category WEB_SERVER; reference:cve,2017-12557; reference:url,www.exploit-db.com/exploits/45952; classtype:web-application-attack; sid:2026719; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2018_12_10, updated_at 2018_12_10;)
` 

Name : **HP Intelligent Management Java Deserialization RCE Attempt** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : cve,2017-12557|url,www.exploit-db.com/exploits/45952

CVE reference : Not defined

Creation date : 2018-12-10

Last modified date : 2018-12-10

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2026552
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER jQuery File Upload Attempt"; flow:established,to_server; content:"POST"; http_method; content:"/php/"; http_uri; content:"name=|22|files|22 3b|"; http_client_body; content:"<?php"; nocase; http_client_body; metadata: former_category WEB_SERVER; reference:url,github.com/lcashdol/Exploits/tree/master/CVE-2018-9206; reference:cve,2018-9206; classtype:web-application-attack; sid:2026552; rev:3; metadata:affected_product PHP, attack_target Server, deployment Datacenter, signature_severity Major, created_at 2018_10_25, updated_at 2018_10_25;)
` 

Name : **jQuery File Upload Attempt** 

Attack target : Server

Description : Not defined

Tags : Not defined

Affected products : PHP

Alert Classtype : web-application-attack

URL reference : url,github.com/lcashdol/Exploits/tree/master/CVE-2018-9206|cve,2018-9206

CVE reference : Not defined

Creation date : 2018-10-25

Last modified date : 2018-10-25

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2027341
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER China Chopper WebShell Observed Outbound"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"<%@|20|Page|20|Language=|22|Jscript|22|%><eval|28|Request.Item|5b|"; fast_pattern; content:"|22 29 3b|%>"; distance:0; within:50; metadata: former_category WEB_SERVER; classtype:trojan-activity; sid:2027341; rev:2; metadata:created_at 2019_05_09, performance_impact Low, updated_at 2019_05_09;)
` 

Name : **China Chopper WebShell Observed Outbound** 

Attack target : Not defined

Description : Alerts on a variant of the China Chopper webshell outbound to the requester.

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-09

Last modified date : 2019-05-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027393
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER China Chopper WebShell Observed Outbound"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|3c 25 40 20|Page|20|Language=|22|Jscript|22 25 3e 3c 25|eval|28|"; fast_pattern; content:"FromBase64String"; distance:0; nocase; content:"|25 3e|"; distance:0; metadata: former_category WEB_SERVER; classtype:trojan-activity; sid:2027393; rev:1; metadata:affected_product Web_Server_Applications, attack_target Server, deployment Perimeter, signature_severity Major, created_at 2019_05_29, performance_impact Low, updated_at 2019_05_29;)
` 

Name : **China Chopper WebShell Observed Outbound** 

Attack target : Server

Description : Alerts on an outbound China Chopper webshell implying it has been requested by an external system.

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-05-29

Last modified date : 2019-05-29

Rev version : 1

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2026731
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER ThinkPHP RCE Exploitation Attempt"; flow:established,to_server; content:"GET"; http_method; content:"/index"; http_uri; content:"/invokefunction&function=call_user_func_array"; http_uri; distance:0; fast_pattern; metadata: former_category WEB_SERVER; reference:url,www.exploit-db.com/exploits/45978; classtype:attempted-admin; sid:2026731; rev:2; metadata:affected_product PHP, attack_target Web_Server, deployment Perimeter, deployment Datacenter, tag ThinkPHP, signature_severity Major, created_at 2018_12_14, performance_impact Low, updated_at 2019_06_03;)
` 

Name : **ThinkPHP RCE Exploitation Attempt** 

Attack target : Web_Server

Description : Alerts on an inbound HTTP GET request containing a URI based on the PoC for the RCE vulnerability.  If successful, the remote attacker will be able to execute code on the receiving system.

Tags : ThinkPHP

Affected products : PHP

Alert Classtype : attempted-admin

URL reference : url,www.exploit-db.com/exploits/45978

CVE reference : Not defined

Creation date : 2018-12-14

Last modified date : 2019-06-03

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027433
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER BlackSquid JSP Webshell Outbound"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"<|25 25|java.io.InputStream|20|"; depth:25; content:"Runtime.getRunetime|28 29|.exec|28|request"; distance:0; within:50; content:".getInputStream|28 29 3b|int|20|"; distance:0; fast_pattern; metadata: former_category WEB_SERVER; reference:url,blog.trendmicro.com/trendlabs-security-intelligence/blacksquid-slithers-into-servers-and-drives-with-8-notorious-exploits-to-drop-xmrig-miner/; classtype:attempted-admin; sid:2027433; rev:1; metadata:attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2019_06_04, performance_impact Low, updated_at 2019_06_04;)
` 

Name : **BlackSquid JSP Webshell Outbound** 

Attack target : Web_Server

Description : Alerts on a possible BlackSquid webshell outbound (implying the system has already been compromised).

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blog.trendmicro.com/trendlabs-security-intelligence/blacksquid-slithers-into-servers-and-drives-with-8-notorious-exploits-to-drop-xmrig-miner/

CVE reference : Not defined

Creation date : 2019-06-04

Last modified date : 2019-06-04

Rev version : 1

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low

# 2027514
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Observed FxCodeShell Web Shell Password"; flow:established,to_server; content:"FxxkMyLie1836710Aa"; http_client_body; metadata: former_category WEB_SERVER; classtype:trojan-activity; sid:2027514; rev:2; metadata:affected_product Web_Server_Applications, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_06_25, malware_family FxCodeShell, performance_impact Low, updated_at 2019_06_26;)
` 

Name : **Observed FxCodeShell Web Shell Password** 

Attack target : Client_Endpoint

Description : This will alert on a password string used in FxCodeShell Web Shell.

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-06-25

Last modified date : 2019-06-26

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : FxCodeShell

Type : SID

Performance Impact : Low

# 2027896
`alert http any any -> any 10000 (msg:"ET WEB_SERVER Webmin RCE CVE-2019-15107"; flow:to_server,established; content:"POST"; http_method; content:"/password_change.cgi"; depth:20; fast_pattern; isdataat:!1,relative; content:"|7c|"; http_client_body; metadata: former_category WEB_SPECIFIC_APPS; reference:url,blog.firosolutions.com/exploits/webmin/; reference:cve,2019-15107; classtype:attempted-admin; sid:2027896; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, deployment Internal, deployment Datacenter, signature_severity Critical, created_at 2019_08_18, updated_at 2019_09_28;)
` 

Name : **Webmin RCE CVE-2019-15107** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : url,blog.firosolutions.com/exploits/webmin/|cve,2019-15107

CVE reference : Not defined

Creation date : 2019-08-18

Last modified date : 2019-09-28

Rev version : 3

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010622
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco Subscriber Edge Services Manager Cross Site Scripting/HTML Injection Attempt"; flow:to_server,established; content:"/servlet/JavascriptProbe"; http_uri; nocase; content:"documentElement=true"; http_uri; nocase; content:"regexp=true"; nocase; http_uri; content:"frames=true"; http_uri; reference:url,www.securityfocus.com/bid/34454/info; reference:url,doc.emergingthreats.net/2010622; classtype:web-application-attack; sid:2010622; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Possible Cisco Subscriber Edge Services Manager Cross Site Scripting/HTML Injection Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/34454/info|url,doc.emergingthreats.net/2010622

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006446
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT"; flow:established,to_server; content:"UNION"; http_uri; nocase; content:"SELECT"; http_uri; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2006446; classtype:web-application-attack; sid:2006446; rev:13; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Possible SQL Injection Attempt UNION SELECT** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2006446

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 13

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016992
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic - *.tar.gz in POST body"; flow:established,to_server; content:"POST"; http_method; content:".tar.gz"; nocase; http_client_body; classtype:bad-unknown; sid:2016992; rev:3; metadata:created_at 2013_06_07, updated_at 2019_08_30;)
` 

Name : **WebShell Generic - *.tar.gz in POST body** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-06-07

Last modified date : 2019-08-30

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023229
`alert dns $HTTP_SERVERS any -> any any (msg:"ET WEB_SERVER DNS Query for Suspicious e5b57288.com Domain - Anuna Checkin - Compromised PHP Site"; dns_query; content:"e5b57288.com"; depth:12; fast_pattern; isdataat:!1,relative; nocase; metadata: former_category WEB_SERVER; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:trojan-activity; sid:2023229; rev:4; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious e5b57288.com Domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : trojan-activity

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023227
`alert dns $HTTP_SERVERS any -> any any (msg:"ET WEB_SERVER DNS Query for Suspicious 33db9538.com Domain - Anuna Checkin - Compromised PHP Site"; dns_query; content:"33db9538.com"; depth:12; fast_pattern; isdataat:!1,relative; nocase; metadata: former_category WEB_SERVER; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:trojan-activity; sid:2023227; rev:4; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious 33db9538.com Domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : trojan-activity

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023228
`alert dns $HTTP_SERVERS any -> any any (msg:"ET WEB_SERVER DNS Query for Suspicious 9507c4e8.com Domain - Anuna Checkin - Compromised PHP Site"; dns_query; content:"9507c4e8.com"; depth:12; fast_pattern; isdataat:!1,relative; nocase; metadata: former_category WEB_SERVER; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:trojan-activity; sid:2023228; rev:4; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious 9507c4e8.com Domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : trojan-activity

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023230
`alert dns $HTTP_SERVERS any -> any any (msg:"ET WEB_SERVER DNS Query for Suspicious 54dfa1cb.com Domain - Anuna Checkin - Compromised PHP Site"; dns_query; content:"54dfa1cb.com"; depth:12; fast_pattern; isdataat:!1,relative; nocase; metadata: former_category WEB_SERVER; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:trojan-activity; sid:2023230; rev:4; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_09_28;)
` 

Name : **DNS Query for Suspicious 54dfa1cb.com Domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : trojan-activity

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-09-28

Rev version : 5

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102061
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL WEB_SERVER Tomcat null byte directory listing attempt"; flow:to_server,established; content:"|00|.jsp"; http_uri; reference:bugtraq,2518; reference:bugtraq,6721; reference:cve,2003-0042; classtype:web-application-attack; sid:2102061; rev:7; metadata:created_at 2010_09_23, updated_at 2019_09_26;)
` 

Name : **Tomcat null byte directory listing attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,2518|bugtraq,6721|cve,2003-0042

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-09-26

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009678
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible DD-WRT Metacharacter Injection Command Execution Attempt"; flow:to_server,established; content:"/cgi-bin/|3B|"; http_uri; nocase; pcre:"/\x2Fcgi\x2Dbin\x2F\x3B.+[a-z]/Ui"; reference:url,isc.sans.org/diary.html?storyid=6853; reference:url,www.theregister.co.uk/2009/07/21/critical_ddwrt_router_vuln/; reference:url,doc.emergingthreats.net/2009678; reference:url,www.dd-wrt.com/phpBB2/viewtopic.php?t=55173; reference:bid,35742; reference:cve,2009-2765; classtype:attempted-admin; sid:2009678; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Possible DD-WRT Metacharacter Injection Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,isc.sans.org/diary.html?storyid=6853|url,www.theregister.co.uk/2009/07/21/critical_ddwrt_router_vuln/|url,doc.emergingthreats.net/2009678|url,www.dd-wrt.com/phpBB2/viewtopic.php?t=55173|bid,35742|cve,2009-2765

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009643
`alert tcp $EXTERNAL_NET any -> $HOME_NET 7777 (msg:"ET WEB_SERVER Oracle Secure Enterprise Search 10.1.8 search Script XSS attempt"; flow:to_server,established; content:"GET "; depth:4; content:"/search/query/search"; nocase; content:"search_p_groups="; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?/i"; reference:url,dsecrg.com/pages/vul/show.php?id=125; reference:url,doc.emergingthreats.net/2009643; classtype:web-application-attack; sid:2009643; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Oracle Secure Enterprise Search 10.1.8 search Script XSS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,dsecrg.com/pages/vul/show.php?id=125|url,doc.emergingthreats.net/2009643

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009644
`alert tcp $EXTERNAL_NET any -> $HOME_NET 7011 (msg:"ET WEB_SERVER Oracle BEA Weblogic Server 10.3 searchQuery XSS attempt"; flow:to_server,established; content:"GET "; depth:4; content:"/consolehelp/console-help.portal"; nocase; content:"searchQuery="; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/i"; reference:url,dsecrg.com/pages/vul/show.php?id=131; reference:url,doc.emergingthreats.net/2009644; classtype:web-application-attack; sid:2009644; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Oracle BEA Weblogic Server 10.3 searchQuery XSS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,dsecrg.com/pages/vul/show.php?id=131|url,doc.emergingthreats.net/2009644

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011244
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (ByroeNet/Casper-Like sun4u)"; flow:established,to_server; content:"|0D 0A|User-Agent|3a| Mozilla/4.76 [ru] (X11|3b| U|3b| SunOS 5.7 sun4u)"; nocase; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; reference:url,doc.emergingthreats.net/2011244; classtype:web-application-attack; sid:2011244; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Bot Search RFI Scan (ByroeNet/Casper-Like sun4u)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/|url,doc.emergingthreats.net/2011244

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011286
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)"; flow:established,to_server; content:"|0D 0A|User-Agent|3a| MaMa "; nocase; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; reference:url,doc.emergingthreats.net/2011286; classtype:web-application-attack; sid:2011286; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/|url,doc.emergingthreats.net/2011286

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010229
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Cherokee Web Server GET AUX Request Denial Of Service Attempt"; flow:established,to_server; content:"GET |2F|AUX HTTP|2F|1|2E|"; nocase; depth:16; reference:url,securitytracker.com/alerts/2009/Oct/1023095.html; reference:url,www.securityfocus.com/bid/36814/info; reference:url,www.securityfocus.com/archive/1/507456; reference:url,doc.emergingthreats.net/2010229; classtype:attempted-dos; sid:2010229; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Cherokee Web Server GET AUX Request Denial Of Service Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,securitytracker.com/alerts/2009/Oct/1023095.html|url,www.securityfocus.com/bid/36814/info|url,www.securityfocus.com/archive/1/507456|url,doc.emergingthreats.net/2010229

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010730
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco ASA Appliance Clientless SSL VPN HTML Rewriting Security Bypass Attempt/Cross Site Scripting Attempt"; flow:to_client,established; content:"CSCO_WebVPN"; nocase; content:"csco_wrap_js"; within:100; nocase; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=18442; reference:url,www.securityfocus.com/archive/1/504516; reference:url,www.securityfocus.com/bid/35476; reference:cve,2009-1201; reference:cve,2009-1202; reference:url,doc.emergingthreats.net/2010730; classtype:web-application-attack; sid:2010730; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Cisco ASA Appliance Clientless SSL VPN HTML Rewriting Security Bypass Attempt/Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,tools.cisco.com/security/center/viewAlert.x?alertId=18442|url,www.securityfocus.com/archive/1/504516|url,www.securityfocus.com/bid/35476|cve,2009-1201|cve,2009-1202|url,doc.emergingthreats.net/2010730

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010519
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 405 XSS Attempt (Local Source)"; flow:from_server,established; content:"HTTP/1.1 405 Method Not Allowed|0d 0a|"; depth:33; nocase; content:"<script"; nocase; within:512; reference:url,doc.emergingthreats.net/2010519; classtype:web-application-attack; sid:2010519; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible HTTP 405 XSS Attempt (Local Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010519

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010521
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 406 XSS Attempt (Local Source)"; flow:from_server,established; content:"HTTP/1.1 406 Not Acceptable|0d 0a|"; depth:29; nocase; content:"<script"; nocase; within:512; reference:url,doc.emergingthreats.net/2010521; classtype:web-application-attack; sid:2010521; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible HTTP 406 XSS Attempt (Local Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010521

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010524
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 500 XSS Attempt (Internal Source)"; flow:from_server,established; content:"HTTP/1.1 500 Internal Server Error|0d 0a|"; depth:36; nocase; content:"<script"; nocase; within:512; reference:url,doc.emergingthreats.net/2010524; classtype:web-application-attack; sid:2010524; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible HTTP 500 XSS Attempt (Internal Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010524

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010526
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 503 XSS Attempt (Internal Source)"; flow:from_server,established; content:"HTTP/1.1 503 Service Unavailable|0d 0a|"; depth:34; nocase; content:"<script"; nocase; within:512; reference:url,doc.emergingthreats.net/2010526; classtype:web-application-attack; sid:2010526; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible HTTP 503 XSS Attempt (Internal Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010526

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000105
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL sp_password attempt"; flow:to_server,established; content:"sp_password"; nocase; reference:url,doc.emergingthreats.net/2000105; classtype:attempted-user; sid:2000105; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQL sp_password attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2000105

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2000106
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL sp_delete_alert attempt"; flow:to_server,established; content:"sp_delete_alert"; nocase; reference:url,doc.emergingthreats.net/2000106; classtype:attempted-user; sid:2000106; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SQL sp_delete_alert attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2000106

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2001768
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER MSSQL Server OLEDB asp error"; flow: established,from_server; content:"Microsoft OLE DB Provider for SQL Server error"; reference:url,www.wiretrip.net/rfp/p/doc.asp/i2/d42.htm; reference:url,doc.emergingthreats.net/2001768; classtype:web-application-activity; sid:2001768; rev:12; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **MSSQL Server OLEDB asp error** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.wiretrip.net/rfp/p/doc.asp/i2/d42.htm|url,doc.emergingthreats.net/2001768

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011287
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Gootkit Website Infection Receiving FTP Credentials from Control Server"; flowbits:isset,ET.GOOTKIT; flow:established,from_server; content:"<acc><login>"; nocase; content:"</login><pass>"; nocase; distance:0; content:"</pass><serv>"; nocase; distance:0; content:"</serv><port>21</port>"; nocase; distance:0; reference:url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp; reference:url,doc.emergingthreats.net/2011287; classtype:web-application-attack; sid:2011287; rev:4; metadata:created_at 2010_09_28, updated_at 2019_09_27;)
` 

Name : **Gootkit Website Infection Receiving FTP Credentials from Control Server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp|url,doc.emergingthreats.net/2011287

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011289
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Local Website Infected By Gootkit"; flow:established,from_server; content:"Gootkit iframer component"; nocase; reference:url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp; reference:url,doc.emergingthreats.net/2011285; classtype:web-application-attack; sid:2011289; rev:4; metadata:created_at 2010_09_28, updated_at 2019_09_27;)
` 

Name : **Local Website Infected By Gootkit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp|url,doc.emergingthreats.net/2011285

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-09-27

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012230
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Likely Malicious Request for /proc/self/environ"; flow:established,to_server; content:"/proc/self/environ"; http_uri; nocase; classtype:web-application-attack; sid:2012230; rev:5; metadata:created_at 2011_01_25, updated_at 2019_09_27;)
` 

Name : **Likely Malicious Request for /proc/self/environ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-01-25

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011806
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER ScriptResource.axd access without t (time) parameter - possible ASP padding-oracle exploit"; flow:established,to_server; content:"GET"; http_method; content:"ScriptResource.axd"; http_uri; nocase; content:!"&t="; http_uri; nocase; content:!"&amp|3b|t="; http_uri; nocase; detection_filter:track by_src,count 15,seconds 2; reference:url,netifera.com/research/; reference:url,www.microsoft.com/technet/security/advisory/2416728.mspx; classtype:web-application-attack; sid:2011806; rev:5; metadata:created_at 2010_10_12, updated_at 2019_09_27;)
` 

Name : **ScriptResource.axd access without t (time) parameter - possible ASP padding-oracle exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,netifera.com/research/|url,www.microsoft.com/technet/security/advisory/2416728.mspx

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011360
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ColdFusion Path Traversal (locale 3/5)"; flow:to_server,established; content:"POST"; http_method; content:"/CFIDE/administrator/entman/index.cfm"; nocase; http_uri; content:"locale=../../"; nocase; reference:url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964; reference:url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/; reference:cve,CVE-2010-2861; reference:url,www.exploit-db.com/exploits/14641/; classtype:web-application-attack; sid:2011360; rev:6; metadata:created_at 2010_09_28, updated_at 2019_09_27;)
` 

Name : **ColdFusion Path Traversal (locale 3/5)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,h30507.www3.hp.com/t5/Following-the-White-Rabbit-A/Adobe-ColdFusion-s-Directory-Traversal-Disaster/ba-p/81964|url,www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/|cve,CVE-2010-2861|url,www.exploit-db.com/exploits/14641/

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010162
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Possible Successful Juniper NetScreen ScreenOS Firmware Version Disclosure Attempt"; flow:established,from_server; content:"Juniper Networks, Inc"; content:"Version|3A|"; within:100; content:"ScreenOS"; distance:0; reference:url,securitytracker.com/alerts/2009/Apr/1022123.html; reference:url,www.securityfocus.com/bid/34710; reference:url,seclists.org/bugtraq/2009/Apr/242; reference:url,www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-05; reference:url,doc.emergingthreats.net/2010162; classtype:attempted-recon; sid:2010162; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Successful Juniper NetScreen ScreenOS Firmware Version Disclosure Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,securitytracker.com/alerts/2009/Apr/1022123.html|url,www.securityfocus.com/bid/34710|url,seclists.org/bugtraq/2009/Apr/242|url,www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-05|url,doc.emergingthreats.net/2010162

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006447
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Attempt UPDATE SET"; flow:established,to_server; content:"UPDATE"; nocase; http_uri; content:"SET"; nocase; distance:0; http_uri; pcre:"/\WUPDATE\s+[A-Za-z0-9$_].*?\WSET\s+[A-Za-z0-9$_].*?\x3d/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2006447; classtype:web-application-attack; sid:2006447; rev:14; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection Attempt UPDATE SET** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2006447

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022860
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Aribitrary File Upload Vulnerability in WP Mobile Detector"; flow:from_client,established; content:"/wp-content/plugins/wp-mobile-detector/"; http_uri; content:"resize.php?src=http"; http_uri; fast_pattern; reference:url,pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/; classtype:attempted-user; sid:2022860; rev:3; metadata:created_at 2016_06_03, updated_at 2019_09_27;)
` 

Name : **Aribitrary File Upload Vulnerability in WP Mobile Detector** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/

CVE reference : Not defined

Creation date : 2016-06-03

Last modified date : 2019-09-27

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011290
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Gootkit Website Infection Request for FTP Credentials from Control Server"; flow:established,to_server; content:"GET"; http_method; content:"/ftp"; nocase; http_uri; content:"User-Agent|3A| Mozilla/4.0 (compatible|3B| Win32|3B| WinHttp.WinHttpRequest"; nocase; http_header; content:!"www.trendmicro.com"; http_header; flowbits:set,ET.GOOTKIT; reference:url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp; reference:url,doc.emergingthreats.net/2011286; classtype:web-application-attack; sid:2011290; rev:8; metadata:created_at 2010_09_28, updated_at 2019_09_27;)
` 

Name : **Gootkit Website Infection Request for FTP Credentials from Control Server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.m86security.com/labs/i/GootKit--Automated-Website-Infection,trace.1368~.asp|url,doc.emergingthreats.net/2011286

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-09-27

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011145
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER 3Com Intelligent Management Center Cross Site Scripting Attempt"; flow:established,to_server; content:"/imc/login.jsf"; http_uri; nocase; content:"loginForm"; http_uri; nocase; content:"javax.faces.ViewState="; http_uri; nocase; pcre:"/ViewState\x3D.+(script|alert|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange)/Ui"; reference:url,securitytracker.com/alerts/2010/May/1024022.html; reference:url,support.3com.com/documents/netmgr/imc/3Com_IMC_readme_plat_3.30-SP2.html; reference:url,www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-02; reference:url,doc.emergingthreats.net/2011145; classtype:web-application-attack; sid:2011145; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **3Com Intelligent Management Center Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,securitytracker.com/alerts/2010/May/1024022.html|url,support.3com.com/documents/netmgr/imc/3Com_IMC_readme_plat_3.30-SP2.html|url,www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-02|url,doc.emergingthreats.net/2011145

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010462
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Barracuda IM Firewall smtp_test.cgi Cross-Site Scripting Attempt"; flow:established,to_server; content:"|2F|cgi|2D|mod|2F|smtp|5F|test|2E|cgi"; http_uri; nocase; content:"email|3D|"; http_uri; nocase; content:"hostname|3D|"; http_uri; nocase; content:"default|5F|domain|3D|"; http_uri; nocase; pcre:"/(script|img|src|alert|onmouse|onkey|onload|ondragdrop|onblur|onfocus|onclick)/Ui"; reference:url,www.securityfocus.com/bid/37248/info; reference:url,doc.emergingthreats.net/2010462; classtype:web-application-attack; sid:2010462; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Barracuda IM Firewall smtp_test.cgi Cross-Site Scripting Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/37248/info|url,doc.emergingthreats.net/2010462

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009715
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt"; flow:to_server,established; content:"onmouseover="; http_uri; nocase; reference:url,www.w3schools.com/jsref/jsref_onmouseover.asp; reference:url,doc.emergingthreats.net/2009715; classtype:web-application-attack; sid:2009715; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Onmouseover= in URI - Likely Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.w3schools.com/jsref/jsref_onmouseover.asp|url,doc.emergingthreats.net/2009715

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010460
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Cisco BBSM Captive Portal AccesCodeStart.asp Cross-Site Scripting Attempt"; flow:established,to_server; content:"|2F|ekgnkm|2F|AccessCodeStart|2E|asp"; http_uri; nocase; pcre:"/(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange)/Ui"; reference:url,www.securityfocus.com/bid/29191/info; reference:cve,2008-2165; reference:url,doc.emergingthreats.net/2010460; classtype:attempted-user; sid:2010460; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Cisco BBSM Captive Portal AccesCodeStart.asp Cross-Site Scripting Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.securityfocus.com/bid/29191/info|cve,2008-2165|url,doc.emergingthreats.net/2010460

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009361
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt"; flow:to_server,established; content:"/cmd.exe"; http_uri; nocase; reference:url,doc.emergingthreats.net/2009361; classtype:attempted-recon; sid:2009361; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **cmd.exe In URI - Possible Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009361

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010919
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER HP LaserJet Printer Cross Site Scripting Attempt"; flow:established,to_server; content:"/support_param.html/config"; http_uri; nocase; content:"Admin_Name=&Admin_Phone="; http_uri; nocase; content:"Product_URL="; http_uri; nocase; pcre:"/(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange).+Apply\x3DApply/Ui"; reference:url,dsecrg.com/pages/vul/show.php?id=148; reference:cve,2009-2684; reference:url,doc.emergingthreats.net/2010919; classtype:web-application-attack; sid:2010919; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **HP LaserJet Printer Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,dsecrg.com/pages/vul/show.php?id=148|cve,2009-2684|url,doc.emergingthreats.net/2010919

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010593
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Microsoft Internet Information Services (IIS) .aspx Filename Extension Parsing File Upload Security Bypass Attempt (aspx)"; flow:established,to_server; content:".aspx|3B 2E|"; http_uri; nocase; reference:url,www.securityfocus.com/bid/37460/info; reference:url,doc.emergingthreats.net/2010593; reference:url,www.securityfocus.com/bid/37460/info; reference:url,soroush.secproject.com/downloadable/iis-semicolon-report.pdf; reference:cve,2009-4444; classtype:web-application-attack; sid:2010593; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Microsoft Internet Information Services (IIS) .aspx Filename Extension Parsing File Upload Security Bypass Attempt (aspx)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/37460/info|url,doc.emergingthreats.net/2010593|url,www.securityfocus.com/bid/37460/info|url,soroush.secproject.com/downloadable/iis-semicolon-report.pdf|cve,2009-4444

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009815
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_cmdshell Stored Procedure Via URI"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_cmdshell"; http_uri; nocase; reference:url,msdn.microsoft.com/en-us/library/ms175046.aspx; reference:url,www.databasejournal.com/features/mssql/article.php/3372131/Using-xpcmdshell.htm; reference:url,doc.emergingthreats.net/2009815; classtype:web-application-attack; sid:2009815; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_cmdshell Stored Procedure Via URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,msdn.microsoft.com/en-us/library/ms175046.aspx|url,www.databasejournal.com/features/mssql/article.php/3372131/Using-xpcmdshell.htm|url,doc.emergingthreats.net/2009815

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009816
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_servicecontrol Stored Procedure Via URI"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_servicecontrol"; http_uri; nocase; pcre:"/(start|stop|continue|pause|querystate)/Ui"; reference:url,www.sqlusa.com/bestpractices2005/administration/xpservicecontrol/; reference:url,doc.emergingthreats.net/2009816; classtype:web-application-attack; sid:2009816; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_servicecontrol Stored Procedure Via URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.sqlusa.com/bestpractices2005/administration/xpservicecontrol/|url,doc.emergingthreats.net/2009816

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009817
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL sp_adduser Stored Procedure Via URI to Create New Database User"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"sp_adduser"; http_uri; nocase; reference:url,technet.microsoft.com/en-us/library/ms181422.aspx; reference:url,doc.emergingthreats.net/2009817; classtype:web-application-attack; sid:2009817; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL sp_adduser Stored Procedure Via URI to Create New Database User** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,technet.microsoft.com/en-us/library/ms181422.aspx|url,doc.emergingthreats.net/2009817

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009818
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_regread/xp_regwrite/xp_regdeletevalue/xp_regdeletekey Stored Procedure Via URI to Modify Registry"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_reg"; http_uri; nocase; pcre:"/xp_reg(read|write|delete)/Ui"; reference:url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm; reference:url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx; reference:url,doc.emergingthreats.net/2009818; classtype:web-application-attack; sid:2009818; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_regread/xp_regwrite/xp_regdeletevalue/xp_regdeletekey Stored Procedure Via URI to Modify Registry** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm|url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx|url,doc.emergingthreats.net/2009818

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009819
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_fileexist Stored Procedure Via URI to Locate Files On Disk"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_fileexist"; http_uri; nocase; reference:url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm; reference:url,www.dugger-it.com/articles/xp_fileexist.asp; reference:url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx; reference:url,doc.emergingthreats.net/2009819; classtype:web-application-attack; sid:2009819; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_fileexist Stored Procedure Via URI to Locate Files On Disk** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm|url,www.dugger-it.com/articles/xp_fileexist.asp|url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx|url,doc.emergingthreats.net/2009819

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009820
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_enumerrorlogs Stored Procedure Via URI to View Error Logs"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_enumerrorlogs"; http_uri; nocase; reference:url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm; reference:url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx; reference:url,doc.emergingthreats.net/2009820; classtype:web-application-attack; sid:2009820; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_enumerrorlogs Stored Procedure Via URI to View Error Logs** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm|url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx|url,doc.emergingthreats.net/2009820

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009822
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_readerrorlogs Stored Procedure Via URI to View Error Logs"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_readerrorlogs"; http_uri; nocase; reference:url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx; reference:url,www.sqlteam.com/article/using-xp_readerrorlog-in-sql-server-2005; reference:url,doc.emergingthreats.net/2009822; classtype:web-application-attack; sid:2009822; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_readerrorlogs Stored Procedure Via URI to View Error Logs** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.sql-server-performance.com/articles/dev/extended_stored_procedures_p1.aspx|url,www.sqlteam.com/article/using-xp_readerrorlog-in-sql-server-2005|url,doc.emergingthreats.net/2009822

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009823
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Attempt To Access MSSQL xp_enumdsn/xp_enumgroups/xp_ntsec_enumdomains Stored Procedure Via URI"; flow:established,to_server; content:"EXEC"; http_uri; nocase; content:"xp_"; http_uri; nocase; content:"_enum"; http_uri; nocase; pcre:"/(xp_enumdsn|xp_enumgroups|xp_ntsec_enumdomains)/Ui"; reference:url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm; reference:url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/; reference:url,msdn.microsoft.com/en-us/library/ms173792.aspx; reference:url,doc.emergingthreats.net/2009823; classtype:web-application-attack; sid:2009823; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Attempt To Access MSSQL xp_enumdsn/xp_enumgroups/xp_ntsec_enumdomains Stored Procedure Via URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.mssqlcity.com/Articles/Undoc/UndocExtSP.htm|url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/|url,msdn.microsoft.com/en-us/library/ms173792.aspx|url,doc.emergingthreats.net/2009823

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011142
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Easteregg Information-Disclosure (php-logo)"; flow:to_server,established; content:"?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"; http_uri; reference:url,osvdb.org/12184; reference:url,www.0php.com/php_easter_egg.php; reference:url,seclists.org/nmap-dev/2010/q2/569; reference:url,doc.emergingthreats.net/2011142; classtype:attempted-recon; sid:2011142; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Easteregg Information-Disclosure (php-logo)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,osvdb.org/12184|url,www.0php.com/php_easter_egg.php|url,seclists.org/nmap-dev/2010/q2/569|url,doc.emergingthreats.net/2011142

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011143
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo)"; flow:to_server,established; content:"?=PHPE9568F35-D428-11d2-A769-00AA001ACF42"; http_uri; reference:url,osvdb.org/12184; reference:url,www.0php.com/php_easter_egg.php; reference:url,seclists.org/nmap-dev/2010/q2/569; reference:url,doc.emergingthreats.net/2011143; classtype:attempted-recon; sid:2011143; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Easteregg Information-Disclosure (zend-logo)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,osvdb.org/12184|url,www.0php.com/php_easter_egg.php|url,seclists.org/nmap-dev/2010/q2/569|url,doc.emergingthreats.net/2011143

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011144
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Easteregg Information-Disclosure (funny-logo)"; flow:to_server,established; content:"?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"; http_uri; reference:url,osvdb.org/12184; reference:url,www.0php.com/php_easter_egg.php; reference:url,seclists.org/nmap-dev/2010/q2/569; reference:url,doc.emergingthreats.net/2011144; classtype:attempted-recon; sid:2011144; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Easteregg Information-Disclosure (funny-logo)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,osvdb.org/12184|url,www.0php.com/php_easter_egg.php|url,seclists.org/nmap-dev/2010/q2/569|url,doc.emergingthreats.net/2011144

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009152
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Generic Remote File Include Attempt (HTTPS)"; flow:to_server,established; content:".php"; http_uri; nocase; content:"=https|3a|/"; http_uri; nocase; pcre:"/\x2Ephp\x3F.{0,300}\x3Dhttps\x3A\x2F[^\x3F\x26]+\x3F/Ui"; reference:url,doc.emergingthreats.net/2009152; classtype:web-application-attack; sid:2009152; rev:10; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Generic Remote File Include Attempt (HTTPS)** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009152

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009153
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Generic Remote File Include Attempt (FTP)"; flow:to_server,established; content:".php"; http_uri; nocase; content:"=ftp|3a|/"; http_uri; nocase; pcre:"/\x2Ephp\x3F.{0,300}\x3Dftp\x3A\x2F[^\x3F\x26]+\x3F/Ui"; reference:url,doc.emergingthreats.net/2009153; classtype:web-application-attack; sid:2009153; rev:10; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Generic Remote File Include Attempt (FTP)** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009153

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009155
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP Generic Remote File Include Attempt (FTPS)"; flow:to_server,established; content:".php"; http_uri; nocase; content:"=ftps\:/"; http_uri; nocase; pcre:"/\x2Ephp\x3F.{0,300}\x3Dftp\x3A\x2F[^\x3F\x26]+\x3F/Ui"; reference:url,doc.emergingthreats.net/2009155; classtype:web-application-attack; sid:2009155; rev:10; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **PHP Generic Remote File Include Attempt (FTPS)** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009155

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 10

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006443
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Attempt DELETE FROM"; flow:established,to_server; content:"DELETE"; http_uri; nocase; content:"FROM"; http_uri; nocase; pcre:"/DELETE.+FROM/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2006443; classtype:web-application-attack; sid:2006443; rev:12; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection Attempt DELETE FROM** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2006443

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 12

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2006444
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQL Injection Attempt INSERT INTO"; flow:established,to_server; content:"INSERT"; http_uri; nocase; content:"INTO"; http_uri; nocase; pcre:"/INSERT.+INTO/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2006444; classtype:web-application-attack; sid:2006444; rev:12; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection Attempt INSERT INTO** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2006444

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 12

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008175
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection (varchar)"; flow:established,to_server; content:"varchar("; http_uri; nocase; reference:url,doc.emergingthreats.net/2008175; classtype:attempted-admin; sid:2008175; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection (varchar)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2008175

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008176
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection (exec)"; flow:established,to_server; content:"exec("; http_uri; nocase; reference:url,doc.emergingthreats.net/2008176; classtype:attempted-admin; sid:2008176; rev:8; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection (exec)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2008176

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008467
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection Attempt Danmec related (declare)"; flow:established,to_server; content:"DECLARE "; http_uri; nocase; content:"CHAR("; http_uri; nocase; content:"CAST("; http_uri; nocase; reference:url,doc.emergingthreats.net/2008467; classtype:attempted-admin; sid:2008467; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL Injection Attempt Danmec related (declare)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2008467

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010084
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible ALTER SQL Injection Attempt"; flow:to_server,established; content:"ALTER"; http_uri; nocase; pcre:"/ALTER\ +(database|procedure|table|column)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/SQl/sql_alter.asp; reference:url,doc.emergingthreats.net/2010084; classtype:web-application-attack; sid:2010084; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible ALTER SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/SQL_Injection|url,www.w3schools.com/SQl/sql_alter.asp|url,doc.emergingthreats.net/2010084

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010085
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible DROP SQL Injection Attempt"; flow:to_server,established; content:"DROP"; http_uri; nocase; pcre:"/DROP\ +(database|procedure|table|column)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/SQl/sql_drop.asp; reference:url,doc.emergingthreats.net/2010085; classtype:web-application-attack; sid:2010085; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible DROP SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/SQL_Injection|url,www.w3schools.com/SQl/sql_drop.asp|url,doc.emergingthreats.net/2010085

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010086
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CREATE SQL Injection Attempt in URI"; flow:to_server,established; content:"CREATE"; http_uri; nocase; pcre:"/CREATE\ +(database|procedure|table|column|directory)/Ui"; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,www.w3schools.com/Sql/sql_create_db.asp; reference:url,doc.emergingthreats.net/2010086; classtype:web-application-attack; sid:2010086; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible CREATE SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/SQL_Injection|url,www.w3schools.com/Sql/sql_create_db.asp|url,doc.emergingthreats.net/2010086

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010965
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SHOW VARIABLES SQL Injection Attempt in URI"; flow:established,to_server; content:"SHOW"; http_uri; nocase; content:"VARIABLES"; http_uri; nocase; pcre:"/SHOW.+VARIABLES/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.1/en/server-system-variables.html; reference:url,doc.emergingthreats.net/2010965; classtype:web-application-attack; sid:2010965; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SHOW VARIABLES SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,dev.mysql.com/doc/refman/5.1/en/server-system-variables.html|url,doc.emergingthreats.net/2010965

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010966
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SHOW CURDATE/CURTIME SQL Injection Attempt in URI"; flow:established,to_server; content:"SHOW"; http_uri; nocase; content:"CUR"; http_uri; nocase; pcre:"/SHOW.+CUR(DATE|TIME)/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curdate; reference:url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curtime; reference:url,doc.emergingthreats.net/2010966; classtype:web-application-attack; sid:2010966; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SHOW CURDATE/CURTIME SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curdate|url,dev.mysql.com/doc/refman/5.1/en/date-and-time-functions.html#function_curtime|url,doc.emergingthreats.net/2010966

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010967
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SHOW TABLES SQL Injection Attempt in URI"; flow:established,to_server; content:"SHOW"; http_uri; nocase; content:"TABLES"; http_uri; nocase; pcre:"/SHOW.+TABLES/Ui"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/4.1/en/show-tables.html; reference:url,doc.emergingthreats.net/2010967; classtype:web-application-attack; sid:2010967; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SHOW TABLES SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,dev.mysql.com/doc/refman/4.1/en/show-tables.html|url,doc.emergingthreats.net/2010967

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011039
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible INSERT VALUES SQL Injection Attempt"; flow:established,to_server; content:"INSERT"; http_uri; nocase; content:"VALUES"; http_uri; nocase; pcre:"/INSERT.+VALUES/Ui"; reference:url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/; reference:url,en.wikipedia.org/wiki/Insert_(SQL); reference:url,doc.emergingthreats.net/2011039; classtype:web-application-attack; sid:2011039; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible INSERT VALUES SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/|url,en.wikipedia.org/wiki/Insert_(SQL)|url,doc.emergingthreats.net/2011039

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011041
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER MYSQL Benchmark Command in URI to Consume Server Resources"; flow:established,to_server; content:"BENCHMARK("; http_uri; nocase; content:")"; http_uri; pcre:"/BENCHMARK\x28[0-9].+\x29/Ui"; reference:url,dev.mysql.com/doc/refman/5.1/en/information-functions.html#function_benchmark; reference:url,doc.emergingthreats.net/2011041; classtype:web-application-attack; sid:2011041; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **MYSQL Benchmark Command in URI to Consume Server Resources** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,dev.mysql.com/doc/refman/5.1/en/information-functions.html#function_benchmark|url,doc.emergingthreats.net/2011041

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011042
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; http_uri; nocase; content:"CONCAT"; http_uri; nocase; pcre:"/SELECT.+CONCAT/Ui"; reference:url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/; reference:url,www.webdevelopersnotes.com/tutorials/sql/a_little_more_on_the_mysql_select_statement.php3; reference:url,doc.emergingthreats.net/2011042; classtype:web-application-attack; sid:2011042; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **MYSQL SELECT CONCAT SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/|url,www.webdevelopersnotes.com/tutorials/sql/a_little_more_on_the_mysql_select_statement.php3|url,doc.emergingthreats.net/2011042

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011122
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL injection obfuscated via REVERSE function"; flow:established,to_server; content:"REVERSE"; http_uri; nocase; pcre:"/[^\w]REVERSE[^\w]?\(/Ui"; reference:url,snosoft.blogspot.com/2010/05/reversenoitcejni-lqs-dnilb-bank-hacking.html; reference:url,doc.emergingthreats.net/2011122; classtype:web-application-attack; sid:2011122; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible SQL injection obfuscated via REVERSE function** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,snosoft.blogspot.com/2010/05/reversenoitcejni-lqs-dnilb-bank-hacking.html|url,doc.emergingthreats.net/2011122

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011073
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Microsoft SharePoint Server 2007 _layouts/help.aspx Cross Site Scripting Attempt"; flow:established,to_server; content:"/_layouts/help.aspx"; http_uri; nocase; content:"cid0="; http_uri; nocase; pcre:"/cid0\x3d.+(script|alert|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange)/Ui"; reference:url,www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=20415; reference:url,www.microsoft.com/technet/security/Bulletin/MS10-039.mspx; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=20610; reference:cve,2010-0817; reference:url,doc.emergingthreats.net/2011073; classtype:web-application-attack; sid:2011073; rev:7; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag XSS, tag Cross_Site_Scripting, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Microsoft SharePoint Server 2007 _layouts/help.aspx Cross Site Scripting Attempt** 

Attack target : Web_Server

Description : Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. 
Cross-site scripting attacks use known vulnerabilities in web-based applications, their servers, or the plug-in systems on which they rely. Exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site. When the resulting combined content arrives at the client-side web browser, it has all been delivered from the trusted source, and thus operates under the permissions granted to that system. By finding ways of injecting malicious scripts into web pages, an attacker can gain elevated access-privileges to sensitive page content, to session cookies, and to a variety of other information maintained by the browser on behalf of the user. There are two general types of XSS attacks:
Persistent: the malicious content is stored on the server
Reflected: the malicious content is delivered by the client or a 3rd party

If this alert is observed, it indicates that an attacker is attempting to establish a XSS attack utilizing your infrastructure. When following up on alerts, one would want to examine the content at the path that was the target of the attack and look for modifications or unwelcome dynamic content such as <script> tags. One could also examine log files for the presence of dynamic content in the URL logs as well. Also, 

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Cross_Site_Scripting, XSS

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html|url,tools.cisco.com/security/center/viewAlert.x?alertId=20415|url,www.microsoft.com/technet/security/Bulletin/MS10-039.mspx|url,tools.cisco.com/security/center/viewAlert.x?alertId=20610|cve,2010-0817|url,doc.emergingthreats.net/2011073

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010159
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible 3Com OfficeConnect Router Default User Account Remote Command Execution Attempt"; flow:established,to_server; content:"/utility.cgi?testType="; http_uri; nocase; content:"IP="; http_uri; nocase; content:"|7C 7C|"; http_uri; pcre:"/\x7C\x7C.+[a-z]/Ui"; reference:url,securitytracker.com/alerts/2009/Oct/1023051.html; reference:url,www.securityfocus.com/archive/1/507263; reference:url,www.securityfocus.com/bid/36722/info; reference:url,doc.emergingthreats.net/2010159; classtype:attempted-admin; sid:2010159; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible 3Com OfficeConnect Router Default User Account Remote Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,securitytracker.com/alerts/2009/Oct/1023051.html|url,www.securityfocus.com/archive/1/507263|url,www.securityfocus.com/bid/36722/info|url,doc.emergingthreats.net/2010159

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010284
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SELECT INSTR in URI Possible ORACLE Related Blind SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; http_uri; nocase; content:"INSTR"; http_uri; nocase; pcre:"/SELECT.+INSTR/Ui"; metadata: former_category WEB_SERVER; reference:url,www.psoug.org/reference/substr_instr.html; reference:url,www.easywebtech.com/artical/Oracle_INSTR.html; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,msdn.microsoft.com/en-us/library/ms161953.aspx; reference:url,doc.emergingthreats.net/2010284; classtype:web-application-attack; sid:2010284; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SELECT INSTR in URI Possible ORACLE Related Blind SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.psoug.org/reference/substr_instr.html|url,www.easywebtech.com/artical/Oracle_INSTR.html|url,www.owasp.org/index.php/SQL_Injection|url,msdn.microsoft.com/en-us/library/ms161953.aspx|url,doc.emergingthreats.net/2010284

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010285
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SELECT SUBSTR/ING in URI Possible Blind SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; http_uri; nocase; content:"SUBSTR"; http_uri; nocase; pcre:"/SELECT.+SUBSTR/Ui"; metadata: former_category WEB_SERVER; reference:url,www.1keydata.com/sql/sql-substring.html; reference:url,www.owasp.org/index.php/SQL_Injection; reference:url,msdn.microsoft.com/en-us/library/ms161953.aspx; reference:url,doc.emergingthreats.net/2010285; classtype:web-application-attack; sid:2010285; rev:8; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **SELECT SUBSTR/ING in URI Possible Blind SQL Injection Attempt** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,www.1keydata.com/sql/sql-substring.html|url,www.owasp.org/index.php/SQL_Injection|url,msdn.microsoft.com/en-us/library/ms161953.aspx|url,doc.emergingthreats.net/2010285

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011763
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco PIX/ASA HTTP Web Interface HTTP Response Splitting Attempt"; flow:established,to_server; content:"GET"; http_method; content:"|0D 0A|Location|3A|"; http_uri; nocase; reference:url,www.secureworks.com/ctu/advisories/SWRX-2010-001/; reference:url,tools.cisco.com/security/center/viewAlert.x?alertId=20737; reference:cve,2008-7257; reference:url,doc.emergingthreats.net/2011763; classtype:web-application-attack; sid:2011763; rev:6; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible Cisco PIX/ASA HTTP Web Interface HTTP Response Splitting Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.secureworks.com/ctu/advisories/SWRX-2010-001/|url,tools.cisco.com/security/center/viewAlert.x?alertId=20737|cve,2008-7257|url,doc.emergingthreats.net/2011763

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009955
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .php~ source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".php~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009955; classtype:web-application-attack; sid:2009955; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .php~ source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009955

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009949
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .pl source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".pl~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009949; classtype:web-application-attack; sid:2009949; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .pl source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009949

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009950
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .inc source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".inc~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009950; classtype:web-application-attack; sid:2009950; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .inc source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009950

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009951
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .conf source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".conf~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009951; classtype:web-application-attack; sid:2009951; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .conf source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009951

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009952
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .asp source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".asp~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009952; classtype:web-application-attack; sid:2009952; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .asp source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009952

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009953
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .aspx source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".aspx~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2009953; classtype:web-application-attack; sid:2009953; rev:14; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .aspx source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2009953

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 14

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010820
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Tilde in URI - potential .cgi source disclosure vulnerability"; flow:established,to_server; content:"GET"; http_method; nocase; content:".cgi~"; http_uri; nocase; metadata: former_category WEB_SERVER; reference:url,seclists.org/fulldisclosure/2009/Sep/0321.html; reference:url,doc.emergingthreats.net/2010820; classtype:web-application-attack; sid:2010820; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Tilde in URI - potential .cgi source disclosure vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,seclists.org/fulldisclosure/2009/Sep/0321.html|url,doc.emergingthreats.net/2010820

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015023
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER IIS 8.3 Filename With Wildcard (Possible File/Dir Bruteforce)"; flow:established,to_server; content:"~1"; http_uri; fast_pattern; pcre:"/([\*\?]~1|~1\.?[\*\?]|\/~1\/)/U"; reference:url,soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf; classtype:network-scan; sid:2015023; rev:4; metadata:created_at 2012_07_04, updated_at 2019_10_07;)
` 

Name : **IIS 8.3 Filename With Wildcard (Possible File/Dir Bruteforce)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : network-scan

URL reference : url,soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

CVE reference : Not defined

Creation date : 2012-07-04

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015480
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Compromised WordPress Server pulling Malicious JS"; flow:established,to_server; content:"/net/?u="; http_uri; fast_pattern; content:"Host|3a 20|net"; http_header; content:"net.net"; http_header; distance:2; within:7; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b 20|MSIE 8.0|3b 20|Windows NT 6.0)"; http_header; pcre:"/^Host\x3a\snet[0-4]{2}net\.net\r?\n$/Hmi"; reference:url,blog.unmaskparasites.com/2012/07/11/whats-in-your-wp-head/; classtype:trojan-activity; sid:2015480; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2012_07_16, updated_at 2019_10_07;)
` 

Name : **Compromised WordPress Server pulling Malicious JS** 

Attack target : Web_Server

Description : WordPress is a free and open-source content management system (CMS) based on PHP and MySQL. Features include a plugin architecture and a template system. WordPress was used by more than 26.4% of the top 10 million websites as of April 2016. WordPress is the most popular blogging system in use on the Web, at more than 60 million websites.

Wordpress vulnerabilities can be with the platform itself, or more commonly, with the plugins and themes. Vulnerabilities in Wordpress itself have been automatically patched since version 3.7 and since that time have become much less common, and vulnerable installations are quickly patched. Plugins are frequently vulnerable and in June 2013, it was found that some of the 50 most downloaded WordPress plugins were vulnerable to common Web attacks such as SQL injection and XSS. A separate inspection of the top-10 e-commerce plugins showed that 7 of them were vulnerable.

After a successful compromise of a site running a vulnerable plugin or theme, attackers often install a backdoor and then use the web server for:

hosting malware downloads
hosting CnC and malware control panels
hosting phish kits
black hat SEO and affiliate redirects
hactivism/defacement

A common step of investigating a WordPress event is to examine the “last modified” date of files and directories within the root of the WordPress installation. Any modified dates near the date of the attack are clear indicators of compromise and warrant further investigation. Also examining your server logs would typically reveal if a non-file modifying attack was successful.

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against a web application.

Tags : Wordpress

Affected products : Wordpress

Alert Classtype : trojan-activity

URL reference : url,blog.unmaskparasites.com/2012/07/11/whats-in-your-wp-head/

CVE reference : Not defined

Creation date : 2012-07-16

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015749
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Oracle SQL Injection utl_inaddr call in URI"; flow:established,to_server; content:"utl_inaddr.get_host"; nocase; http_uri; fast_pattern; classtype:attempted-admin; sid:2015749; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2012_09_28, updated_at 2019_10_07;)
` 

Name : **Possible Oracle SQL Injection utl_inaddr call in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-09-28

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015926
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WebShell - Unknown - .php?x=img&img="; flow:established,to_server; content:".php?x=img&img="; http_uri; fast_pattern; classtype:web-application-activity; sid:2015926; rev:3; metadata:created_at 2012_11_23, updated_at 2019_10_07;)
` 

Name : **WebShell - Unknown - .php?x=img&img=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-23

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016415
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP tag in UA"; flow:established,to_server; content:"<?php"; http_user_agent; nocase; fast_pattern; reference:url,blog.spiderlabs.com/2013/02/honeypot-alert-user-agent-field-php-injection-attacks.html; classtype:bad-unknown; sid:2016415; rev:4; metadata:created_at 2013_02_16, updated_at 2019_10_07;)
` 

Name : **PHP tag in UA** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blog.spiderlabs.com/2013/02/honeypot-alert-user-agent-field-php-injection-attacks.html

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016416
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER base64_decode in UA"; flow:established,to_server; content:"base64_decode("; http_user_agent; nocase; fast_pattern; reference:url,blog.spiderlabs.com/2013/02/honeypot-alert-user-agent-field-php-injection-attacks.html; classtype:bad-unknown; sid:2016416; rev:4; metadata:created_at 2013_02_16, updated_at 2019_10_07;)
` 

Name : **base64_decode in UA** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,blog.spiderlabs.com/2013/02/honeypot-alert-user-agent-field-php-injection-attacks.html

CVE reference : Not defined

Creation date : 2013-02-16

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016641
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Perl Shell in HTTP POST"; flow:established,to_server; content:"POST"; nocase; http_method; content:"#!/usr/bin/perl"; nocase; http_client_body; fast_pattern; reference:url,isc.sans.edu/diary.html?storyid=9478; classtype:web-application-attack; sid:2016641; rev:7; metadata:created_at 2013_03_21, updated_at 2019_10_07;)
` 

Name : **Possible Perl Shell in HTTP POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,isc.sans.edu/diary.html?storyid=9478

CVE reference : Not defined

Creation date : 2013-03-21

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016642
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Perl Shell in HTTP POST"; flow:established,to_server; content:"POST"; nocase; http_method; content:"#!/bin/sh"; nocase; http_client_body; fast_pattern; reference:url,isc.sans.edu/diary.html?storyid=9478; classtype:web-application-attack; sid:2016642; rev:7; metadata:created_at 2013_03_21, updated_at 2019_10_07;)
` 

Name : **Possible Perl Shell in HTTP POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,isc.sans.edu/diary.html?storyid=9478

CVE reference : Not defined

Creation date : 2013-03-21

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011768
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PHP tags in HTTP POST"; flow:established,to_server; content:"POST"; nocase; http_method; content:"<?php"; nocase; http_client_body; fast_pattern; reference:url,isc.sans.edu/diary.html?storyid=9478; classtype:web-application-attack; sid:2011768; rev:7; metadata:created_at 2010_09_28, updated_at 2019_10_07;)
` 

Name : **PHP tags in HTTP POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,isc.sans.edu/diary.html?storyid=9478

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016672
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER SQL Errors in HTTP 200 Response (error in your SQL syntax)"; flow:from_server,established; content:"200"; http_stat_code; file_data; content:"error in your SQL syntax"; fast_pattern; classtype:bad-unknown; sid:2016672; rev:3; metadata:created_at 2013_03_27, updated_at 2019_10_07;)
` 

Name : **SQL Errors in HTTP 200 Response (error in your SQL syntax)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-27

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016920
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Apache Struts Possible xwork Disable Method Execution"; flow:established,to_server; content:"xwork"; http_uri; nocase; content:"MethodAccessor"; http_uri; nocase; content:"denyMethodExecution"; http_uri; nocase; fast_pattern; reference:url,struts.apache.org/development/2.x/docs/s2-013.html; classtype:attempted-admin; sid:2016920; rev:3; metadata:created_at 2013_05_23, updated_at 2019_10_07;)
` 

Name : **Apache Struts Possible xwork Disable Method Execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,struts.apache.org/development/2.x/docs/s2-013.html

CVE reference : Not defined

Creation date : 2013-05-23

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016918
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible NGINX Overflow CVE-2013-2028 Exploit Specific"; flow:established,to_server; content:"chunked"; http_header; nocase; fast_pattern; pcre:"/Transfer-Encoding\x3a[^\r\n]*?chunked/Hi"; pcre:"/^[\r\n\s]*?[^\r\n]+HTTP\/1\.\d[^\r\n]*?\r?\n((?!(\r?\n\r?\n)).)*?Transfer-Encoding\x3a[^\r\n]*?Chunked((?!(\r?\n\r?\n)).)*?\r?\n\r?\n[\r\n\s]*?(f{6}[8-9a-f][0-9a-f]|[a-f0-9]{9})/si"; reference:url,www.vnsecurity.net/2013/05/analysis-of-nginx-cve-2013-2028/; reference:url,github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/nginx_chunked_size.rb; classtype:attempted-admin; sid:2016918; rev:7; metadata:created_at 2013_05_22, updated_at 2019_10_07;)
` 

Name : **Possible NGINX Overflow CVE-2013-2028 Exploit Specific** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.vnsecurity.net/2013/05/analysis-of-nginx-cve-2013-2028/|url,github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/nginx_chunked_size.rb

CVE reference : Not defined

Creation date : 2013-05-22

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016936
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE"; flow:established,to_server; content:"LOAD_FILE("; http_uri; nocase; fast_pattern; reference:url,dev.mysql.com/doc/refman/5.1/en/string-functions.html#function_load-file; reference:url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet; classtype:web-application-attack; sid:2016936; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2013_05_28, updated_at 2019_10_07;)
` 

Name : **SQL Injection Local File Access Attempt Using LOAD_FILE** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,dev.mysql.com/doc/refman/5.1/en/string-functions.html#function_load-file|url,pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

CVE reference : Not defined

Creation date : 2013-05-28

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016977
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER allow_url_include PHP config option in uri"; flow:established,to_server; content:"allow_url_include"; http_uri; fast_pattern; pcre:"/\ballow_url_include\s*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016977; rev:4; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **allow_url_include PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016978
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER safe_mode PHP config option in uri"; flow:established,to_server; content:"safe_mode"; http_uri; fast_pattern; pcre:"/\bsafe_mode\s*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016978; rev:4; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **safe_mode PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016981
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER open_basedir PHP config option in uri"; flow:established,to_server; content:"open_basedir"; http_uri; fast_pattern; pcre:"/\bopen_basedir\s*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016981; rev:5; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **open_basedir PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016982
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER auto_prepend_file PHP config option in uri"; flow:established,to_server; content:"auto_prepend_file"; http_uri; fast_pattern; pcre:"/\bauto_prepend_file\s*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016982; rev:4; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **auto_prepend_file PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016979
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER suhosin.simulation PHP config option in uri"; flow:established,to_server; content:"suhosin.simulation"; http_uri; fast_pattern; pcre:"/\bsuhosin\.simulation\s*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016979; rev:5; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **suhosin.simulation PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016980
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER disable_functions PHP config option in uri"; flow:established,to_server; content:"disable_functions"; http_uri; fast_pattern; pcre:"/\bdisable_functions[\s\+]*?=/U"; reference:url,seclists.org/fulldisclosure/2013/Jun/21; classtype:trojan-activity; sid:2016980; rev:6; metadata:created_at 2013_06_05, updated_at 2019_10_07;)
` 

Name : **disable_functions PHP config option in uri** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/fulldisclosure/2013/Jun/21

CVE reference : Not defined

Creation date : 2013-06-05

Last modified date : 2019-10-07

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017010
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible SQLi xp_cmdshell POST body"; flow:established,to_server; content:"xp_cmdshell"; nocase; http_client_body; fast_pattern; classtype:bad-unknown; sid:2017010; rev:4; metadata:created_at 2013_06_12, updated_at 2019_10_07;)
` 

Name : **Possible SQLi xp_cmdshell POST body** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-06-12

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017091
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - Pouya - URI - action="; flow:established,to_server; content:".asp?action="; http_uri; nocase; fast_pattern; pcre:"/\.asp\?action=(?:txt(?:edit|view)|upload|info|del)(&|$)/Ui"; classtype:trojan-activity; sid:2017091; rev:3; metadata:created_at 2013_07_02, updated_at 2019_10_07;)
` 

Name : **WebShell - Pouya - URI - action=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017143
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER CRLF Injection - Newline Characters in URL"; flow:established,to_server; content:"|0D 0A|"; fast_pattern; http_uri; pcre:"/[\n\r](?:content-(type|length)|set-cookie|location)\x3a/Ui"; reference:url,www.owasp.org/index.php/CRLF_Injection; classtype:web-application-attack; sid:2017143; rev:4; metadata:created_at 2013_07_12, updated_at 2019_10_07;)
` 

Name : **CRLF Injection - Newline Characters in URL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.owasp.org/index.php/CRLF_Injection

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017277
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible Apache Struts OGNL in Dynamic Action"; flow:established,to_server; content:"/${"; http_uri; fast_pattern; pcre:"/\/\$\{[^\}\x2c]+?=/U"; reference:cve,2013-2135; reference:bugtraq,60345; reference:url,cwiki.apache.org/confluence/display/WW/S2-015; classtype:attempted-user; sid:2017277; rev:5; metadata:created_at 2013_08_06, updated_at 2019_10_07;)
` 

Name : **Possible Apache Struts OGNL in Dynamic Action** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2013-2135|bugtraq,60345|url,cwiki.apache.org/confluence/display/WW/S2-015

CVE reference : Not defined

Creation date : 2013-08-06

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017327
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Joomla Upload File Filter Bypass"; flow:established,to_server; content:"option=com_media"; http_uri; nocase; fast_pattern; content:"Filedata[]"; http_client_body; nocase; pcre:"/filename[\r\n\s]*?=[\r\n\s]*?[\x22\x27]?[^\r\n\x22\x27\x3b]+?\.[\r\n\x3b\x22\x27]/Pi"; classtype:attempted-user; sid:2017327; rev:3; metadata:created_at 2013_08_14, updated_at 2019_10_07;)
` 

Name : **Joomla Upload File Filter Bypass** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-14

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017366
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Coldfusion 9 Auth Bypass CVE-2013-0632"; flow:to_server; content:"POST"; http_method; content:"/adminapi/administrator.cfc?"; http_uri; nocase; content:"method"; http_uri; nocase; content:"login"; http_uri; nocase; content:"rdsPasswordAllowed"; nocase; http_client_body; fast_pattern; pcre:"/rdsPasswordAllowed[\r\n\s]*?=[\r\n\s]*?(true|1)/Pi"; reference:url,www.exploit-db.com/exploits/27755/; reference:cve,2013-0632; classtype:attempted-user; sid:2017366; rev:3; metadata:created_at 2013_08_21, updated_at 2019_10_07;)
` 

Name : **Coldfusion 9 Auth Bypass CVE-2013-0632** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.exploit-db.com/exploits/27755/|cve,2013-0632

CVE reference : Not defined

Creation date : 2013-08-21

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017399
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic eval of base64_decode"; flow:established,from_server; file_data; content:"base64_decode"; nocase; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?base64_decode/Rsi"; classtype:trojan-activity; sid:2017399; rev:8; metadata:created_at 2013_08_30, updated_at 2019_10_07;)
` 

Name : **WebShell Generic eval of base64_decode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2019-10-07

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017400
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic eval of gzinflate"; flow:established,from_server; file_data; content:"gzinflate"; nocase; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?gzinflate/Rsi"; classtype:trojan-activity; sid:2017400; rev:8; metadata:created_at 2013_08_30, updated_at 2019_10_07;)
` 

Name : **WebShell Generic eval of gzinflate** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2019-10-07

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017401
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic eval of str_rot13"; flow:established,from_server; file_data; content:"str_rot13"; nocase; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?str_rot13/Rsi"; classtype:trojan-activity; sid:2017401; rev:8; metadata:created_at 2013_08_30, updated_at 2019_10_07;)
` 

Name : **WebShell Generic eval of str_rot13** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2019-10-07

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017402
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic eval of gzuncompress"; flow:established,from_server; file_data; content:"gzuncompress"; nocase; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?gzuncompress/Rsi"; classtype:trojan-activity; sid:2017402; rev:8; metadata:created_at 2013_08_30, updated_at 2019_10_07;)
` 

Name : **WebShell Generic eval of gzuncompress** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2019-10-07

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017403
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell Generic eval of convert_uudecode"; flow:established,from_server; file_data; content:"convert_uudecode"; nocase; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?convert_uudecode/Rsi"; classtype:trojan-activity; sid:2017403; rev:8; metadata:created_at 2013_08_30, updated_at 2019_10_07;)
` 

Name : **WebShell Generic eval of convert_uudecode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-30

Last modified date : 2019-10-07

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017436
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP SERVER SuperGlobal in URI"; flow:established,to_server; content:"_SERVER["; fast_pattern; http_uri; pcre:"/[&\?]_SERVER\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017436; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP SERVER SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017437
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP GET SuperGlobal in URI"; flow:established,to_server; content:"_GET["; fast_pattern; http_uri; pcre:"/[&\?]_GET\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017437; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP GET SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017438
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP POST SuperGlobal in URI"; flow:established,to_server; content:"_POST["; fast_pattern; http_uri; pcre:"/[&\?]_POST\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017438; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP POST SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017439
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP COOKIE SuperGlobal in URI"; flow:established,to_server; content:"_COOKIE["; fast_pattern; http_uri; pcre:"/[&\?]_COOKIE\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017439; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP COOKIE SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017440
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP SESSION SuperGlobal in URI"; flow:established,to_server; content:"_SESSION["; fast_pattern; http_uri; pcre:"/[&\?]_SESSION\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017440; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP SESSION SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017441
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP REQUEST SuperGlobal in URI"; flow:established,to_server; content:"_REQUEST["; fast_pattern; http_uri; pcre:"/[&\?]_REQUEST\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017441; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP REQUEST SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017442
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP ENV SuperGlobal in URI"; flow:established,to_server; content:"_ENV["; fast_pattern; http_uri; pcre:"/[&\?]_ENV\[[^\]]+?\][^=]*?=/U"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017442; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP ENV SuperGlobal in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017443
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP SERVER SuperGlobal in POST"; flow:established,to_server; content:"_SERVER["; fast_pattern; http_client_body; pcre:"/(?:[&\?\r\n]|^)_SERVER\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017443; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP SERVER SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017444
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP GET SuperGlobal in POST"; flow:established,to_server; content:"_GET["; fast_pattern; http_client_body; pcre:"/(?:[&\?\r\n]|^)_GET\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017444; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP GET SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017445
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP POST SuperGlobal in POST"; flow:established,to_server; content:"_POST["; fast_pattern; http_client_body; pcre:"/(?:[&\?\r\n]|^)_POST\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017445; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP POST SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017446
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP COOKIE SuperGlobal in POST"; flow:established,to_server; content:"_COOKIE["; fast_pattern; http_client_body; pcre:"/[&\?]_COOKIE\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017446; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP COOKIE SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017447
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP SESSION SuperGlobal in POST"; flow:established,to_server; content:"_SESSION["; fast_pattern; http_client_body; pcre:"/[&\?]_SESSION\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017447; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP SESSION SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017448
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP REQUEST SuperGlobal in POST"; flow:established,to_server; content:"_REQUEST["; fast_pattern; http_client_body; pcre:"/[&\?]_REQUEST\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017448; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP REQUEST SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017449
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHP ENV SuperGlobal in POST"; flow:established,to_server; content:"_ENV["; fast_pattern; http_client_body; pcre:"/[&\?]_ENV\[[^\]]+?\][^=]*?=/P"; reference:url,imperva.com/download.asp?id=421; classtype:bad-unknown; sid:2017449; rev:3; metadata:created_at 2013_09_10, updated_at 2019_10_07;)
` 

Name : **PHP ENV SuperGlobal in POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,imperva.com/download.asp?id=421

CVE reference : Not defined

Creation date : 2013-09-10

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017734
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WEBSHELL pwn.jsp shell"; flow:established,to_server; content:"/pwn.jsp?"; http_uri; nocase; fast_pattern; content:"cmd="; http_uri; nocase; reference:url,nickhumphreyit.blogspot.co.il/2013/10/jboss-42-hacked-by-pwnjsp.html; reference:url,blog.imperva.com/2013/11/threat-advisory-a-jboss-as-exploit-web-shell-code-injection.html; classtype:attempted-admin; sid:2017734; rev:5; metadata:created_at 2013_11_19, updated_at 2019_10_07;)
` 

Name : **WEBSHELL pwn.jsp shell** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,nickhumphreyit.blogspot.co.il/2013/10/jboss-42-hacked-by-pwnjsp.html|url,blog.imperva.com/2013/11/threat-advisory-a-jboss-as-exploit-web-shell-code-injection.html

CVE reference : Not defined

Creation date : 2013-11-19

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017820
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER IIS ISN BackDoor Command GetLog"; flow:established,to_server; content:"isn_getlog"; http_uri; nocase; fast_pattern; pcre:"/[?&]isn_getlog/Ui"; reference:url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html; classtype:trojan-activity; sid:2017820; rev:6; metadata:created_at 2013_12_09, updated_at 2019_10_07;)
` 

Name : **IIS ISN BackDoor Command GetLog** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2019-10-07

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017875
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Coldfusion cfcexplorer Directory Traversal"; flow:established,to_server; content:"/cfcexplorer.cfc"; nocase; http_uri; fast_pattern; content:"path="; nocase; pcre:"/^[^&]*?(?:%(?:25)?2e(?:%(?:(?:25)?2e(?:%(?:25)?5c|\/|\\)|2e(?:25)?%(?:25)?2f)|\.(?:%(?:25)?(?:2f|5c)|\/|\\))|\.(?:%(?:25)?2e(?:%(?:25)?(?:2f|5c)|\/|\\)|\.(?:%(?:25)?(?:2f|5c)|\/|\\)))/Ri"; reference:url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module-prologue-method-of-entry-analysis.html; classtype:attempted-user; sid:2017875; rev:3; metadata:created_at 2013_12_16, updated_at 2019_10_07;)
` 

Name : **Coldfusion cfcexplorer Directory Traversal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module-prologue-method-of-entry-analysis.html

CVE reference : Not defined

Creation date : 2013-12-16

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017882
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Apache Solr Arbitrary XSLT inclusion attack"; flow:to_server,established; content:"../../"; fast_pattern; content:"&wt=xslt"; nocase; content:"&tr="; reference:cve,CVE-2013-6397; reference:url,www.agarri.fr/kom/archives/2013/11/27/compromising_an_unreachable_solr_server_with_cve-2013-6397/index.html; classtype:attempted-user; sid:2017882; rev:3; metadata:created_at 2013_12_17, updated_at 2019_10_07;)
` 

Name : **Apache Solr Arbitrary XSLT inclusion attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,CVE-2013-6397|url,www.agarri.fr/kom/archives/2013/11/27/compromising_an_unreachable_solr_server_with_cve-2013-6397/index.html

CVE reference : Not defined

Creation date : 2013-12-17

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018056
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY."; flow:established,to_server; content:"DOCTYPE"; http_client_body; nocase; fast_pattern; content:"SYSTEM"; nocase; http_client_body; content:"ENTITY"; nocase; pcre:"/^\s+?[^\s\>]+?\s+?SYSTEM\s/Ri"; classtype:trojan-activity; sid:2018056; rev:3; metadata:created_at 2014_02_03, updated_at 2019_10_07;)
` 

Name : **Possible XXE SYSTEM ENTITY in POST BODY.** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-02-03

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018113
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Apache Tomcat Boundary Overflow DOS/File Upload Attempt"; flow:established,to_server; content:"POST"; http_method; content:"multipart/form-data"; http_header; fast_pattern; content:"Content-Type|3a|"; nocase; pcre:"/^[^\r\n]*?boundary\s*?=\s*?[^\r\n]/Ri"; isdataat:4091,relative; content:!"|0A|"; within:4091; reference:url,blog.spiderlabs.com/2014/02/cve-2014-0050-exploit-with-boundaries-loops-without-boundaries.html; reference:cve,2014-0050; classtype:web-application-attack; sid:2018113; rev:3; metadata:created_at 2014_02_12, updated_at 2019_10_07;)
` 

Name : **Apache Tomcat Boundary Overflow DOS/File Upload Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.spiderlabs.com/2014/02/cve-2014-0050-exploit-with-boundaries-loops-without-boundaries.html|cve,2014-0050

CVE reference : Not defined

Creation date : 2014-02-12

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018202
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER log4jAdmin access from non-local network (can modify logging levels)"; flow:established,to_server; content:"/log4jAdmin.jsp"; http_uri; fast_pattern; reference:url, gist.github.com/iamkristian/943918; classtype:web-application-activity; sid:2018202; rev:3; metadata:created_at 2014_03_03, updated_at 2019_10_07;)
` 

Name : **log4jAdmin access from non-local network (can modify logging levels)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url, gist.github.com/iamkristian/943918

CVE reference : Not defined

Creation date : 2014-03-03

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018203
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER log4jAdmin access from non-local network Page Body (can modify logging levels)"; flow:established,from_server; file_data; content:"<title>Log4J Administration</title>"; fast_pattern; content:"Change Log Level To"; reference:url, gist.github.com/iamkristian/943918; classtype:web-application-activity; sid:2018203; rev:3; metadata:created_at 2014_03_03, updated_at 2019_10_07;)
` 

Name : **log4jAdmin access from non-local network Page Body (can modify logging levels)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url, gist.github.com/iamkristian/943918

CVE reference : Not defined

Creation date : 2014-03-03

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018370
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ATTACKER WebShell - Zehir4.asp"; flow:established,to_server; content:".asp?mevla=1"; http_uri; nocase; fast_pattern; reference:url,pastebin.com/m44e60e60; reference:url,www.fidelissecurity.com/webfm_send/377; classtype:web-application-attack; sid:2018370; rev:5; metadata:created_at 2014_04_07, updated_at 2019_10_07;)
` 

Name : **ATTACKER WebShell - Zehir4.asp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,pastebin.com/m44e60e60|url,www.fidelissecurity.com/webfm_send/377

CVE reference : Not defined

Creation date : 2014-04-07

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018601
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER c99 Shell Backdoor Var Override URI"; flow:to_server,established; content:"c99shcook["; nocase; http_uri; fast_pattern; pcre:"/[&?]c99shcook\[/Ui"; reference:url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/; classtype:trojan-activity; sid:2018601; rev:3; metadata:created_at 2014_06_24, updated_at 2019_10_07;)
` 

Name : **c99 Shell Backdoor Var Override URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/

CVE reference : Not defined

Creation date : 2014-06-24

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018602
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER c99 Shell Backdoor Var Override Cookie"; flow:to_server,established; content:"c99shcook"; nocase; fast_pattern; pcre:"/c99shcook/Ci"; reference:url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/; classtype:trojan-activity; sid:2018602; rev:3; metadata:created_at 2014_06_24, updated_at 2019_10_07;)
` 

Name : **c99 Shell Backdoor Var Override Cookie** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/

CVE reference : Not defined

Creation date : 2014-06-24

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2018603
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER c99 Shell Backdoor Var Override Client Body"; flow:to_server,established; content:"c99shcook["; nocase; fast_pattern; http_client_body; pcre:"/(?:^|&)c99shcook\[/Pi"; reference:url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/; classtype:trojan-activity; sid:2018603; rev:3; metadata:created_at 2014_06_24, updated_at 2019_10_07;)
` 

Name : **c99 Shell Backdoor Var Override Client Body** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/

CVE reference : Not defined

Creation date : 2014-06-24

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019110
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Likely Malicious Request for /proc/self/fd/"; flow:established,to_server; content:"/proc/self/fd/"; nocase; http_uri; fast_pattern; classtype:web-application-attack; sid:2019110; rev:3; metadata:created_at 2014_09_04, updated_at 2019_10_07;)
` 

Name : **Likely Malicious Request for /proc/self/fd/** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-09-04

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019182
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HTTP POST Generic eval of base64_decode"; flow:established,to_server; content:"base64_decode"; nocase; http_client_body; fast_pattern; content:"eval"; nocase; pcre:"/^[\r\n\s]*?\x28[\r\n\s]*?base64_decode/Rsi"; classtype:trojan-activity; sid:2019182; rev:3; metadata:created_at 2014_09_16, updated_at 2019_10_07;)
` 

Name : **HTTP POST Generic eval of base64_decode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-09-16

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015737
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER PHPMyAdmin BackDoor Access"; flow:established,to_server; content:"POST"; http_method; content:"/server_sync.php?"; fast_pattern; http_uri; content:"c="; http_uri; pcre:"/\/server_sync.php\?(?:.+?&)?c=/Ui"; reference:url,www.phpmyadmin.net/home_page/security/PMASA-2012-5.php; classtype:attempted-admin; sid:2015737; rev:7; metadata:created_at 2012_09_25, updated_at 2019_10_07;)
` 

Name : **PHPMyAdmin BackDoor Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.phpmyadmin.net/home_page/security/PMASA-2012-5.php

CVE reference : Not defined

Creation date : 2012-09-25

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019234
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in Client Body 2"; flow:established,to_server; content:"|25|28|25|29|25|20|25|7b|25|20"; http_client_body; fast_pattern; pcre:"/(:?(:?\x5e|%5e)|(:?[=?&]|\x25(:?3d|3f|26)))\s*?(:?%28|\x28)(:?%29|\x29)(:?%20|\x20)(:?%7b|\x7b)(:?%20|\x20)/Pi"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019234; rev:5; metadata:created_at 2014_09_24, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in Client Body 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-24

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019291
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER CVE-2014-6271 Attempt In HTTP Headers Line Continuation Evasion LF"; flow:to_server,established; content:"|28 29 0a 20 7b|"; fast_pattern; reference:url,www.invisiblethreat.ca/2014/09/cve-2014-6271/; classtype:attempted-admin; sid:2019291; rev:3; metadata:created_at 2014_09_28, updated_at 2019_10_07;)
` 

Name : **CVE-2014-6271 Attempt In HTTP Headers Line Continuation Evasion LF** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.invisiblethreat.ca/2014/09/cve-2014-6271/

CVE reference : Not defined

Creation date : 2014-09-28

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019292
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER CVE-2014-6271 Attempt In HTTP Headers Line Continuation Evasion CRLF"; flow:to_server,established; content:"|28 29 0d 0a 20 7b|"; fast_pattern; reference:url,www.invisiblethreat.ca/2014/09/cve-2014-6271/; classtype:attempted-admin; sid:2019292; rev:4; metadata:created_at 2014_09_28, updated_at 2019_10_07;)
` 

Name : **CVE-2014-6271 Attempt In HTTP Headers Line Continuation Evasion CRLF** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,www.invisiblethreat.ca/2014/09/cve-2014-6271/

CVE reference : Not defined

Creation date : 2014-09-28

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019308
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER CURL Command Specifying Output in HTTP Headers"; flow:established,to_server; content:"curl "; fast_pattern; http_header; pcre:"/(?!^User-Agent\x3a)\bcurl\s[^\r\n]*?-(?:[Oo]|-(?:remote-name|output))[^\r\n]+(?:\x3b|&&)/Hm"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019308; rev:3; metadata:created_at 2014_09_29, updated_at 2019_10_07;)
` 

Name : **CURL Command Specifying Output in HTTP Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-29

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019309
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WGET Command Specifying Output in HTTP Headers"; flow:established,to_server; content:"wget "; fast_pattern; http_header; pcre:"/(?!^User-Agent\x3a)\bwget\s[^\r\n]+(?:\x3b|&&)/Hm"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019309; rev:3; metadata:created_at 2014_09_29, updated_at 2019_10_07;)
` 

Name : **WGET Command Specifying Output in HTTP Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-29

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019310
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER lwp-download Command Specifying Output in HTTP Headers"; flow:established,to_server; content:"lwp-download "; fast_pattern; http_header; pcre:"/(?!^User-Agent\x3a)\blwp-download\s[^\r\n]+(?:\x3b|&&)/Hm"; metadata: former_category WEB_SERVER; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019310; rev:3; metadata:created_at 2014_09_29, updated_at 2019_10_07;)
` 

Name : **lwp-download Command Specifying Output in HTTP Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-29

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019314
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible bash shell piped to dev udp Inbound to WebServer"; flow:established,to_server; content:"/dev/udp/"; fast_pattern; classtype:bad-unknown; sid:2019314; rev:4; metadata:created_at 2014_09_29, updated_at 2019_10_07;)
` 

Name : **Possible bash shell piped to dev udp Inbound to WebServer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-09-29

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019285
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible bash shell piped to dev tcp Inbound to WebServer"; flow:established,to_server; content:"/dev/tcp/"; fast_pattern; classtype:bad-unknown; sid:2019285; rev:4; metadata:created_at 2014_09_26, updated_at 2019_10_07;)
` 

Name : **Possible bash shell piped to dev tcp Inbound to WebServer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-09-26

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019231
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in URI"; flow:established,to_server; content:"|28 29 20 7b|"; http_uri; fast_pattern; pcre:"/[=?&\x2f]\s*?\x28\x29\x20\x7b/U"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019231; rev:5; metadata:created_at 2014_09_24, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-24

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019232
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers"; flow:established,to_server; content:"|28 29 20 7b|"; http_header; fast_pattern; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019232; rev:5; metadata:created_at 2014_09_24, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in Headers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-24

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019233
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in Client Body"; flow:established,to_server; content:"|28 29 20 7b|"; http_client_body; fast_pattern; pcre:"/(?:^|[=?&])\s*?\x28\x29\x20\x7b/P";  reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019233; rev:5; metadata:created_at 2014_09_24, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in Client Body** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-24

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019236
`alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number"; flow:established,to_server; content:"|20 28 29 20 7b|"; fast_pattern; pcre:"/^[^\s]+\s+[^\s]+\s+\x28\x29\x20\x7b[^\r\n]*?\r?$/m"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019236; rev:4; metadata:created_at 2014_09_25, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in HTTP Version Number** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019241
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in Client Body 3"; flow:established,to_server; content:"()|25|20|25|7b"; http_client_body; fast_pattern; pcre:"/(:?(?:\x5e|%5e)|([=?&]|\x25(?:3d|3f|26)))\s*?\(\)(?:%20|\x20)(?:%7b|\x7b)/Pi"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019241; rev:4; metadata:created_at 2014_09_25, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt in Client Body 3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2014-09-25

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019460
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER MongoDB Negated Parameter Server Side JavaScript Injection Attempt"; flow:established,to_server; content:"[$ne]"; http_uri; fast_pattern; reference:url,blog.imperva.com/2014/10/nosql-ssji-authentication-bypass.html; reference:url,docs.mongodb.org/manual/reference/operator/query/ne/; classtype:web-application-attack; sid:2019460; rev:3; metadata:created_at 2014_10_17, updated_at 2019_10_07;)
` 

Name : **MongoDB Negated Parameter Server Side JavaScript Injection Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.imperva.com/2014/10/nosql-ssji-authentication-bypass.html|url,docs.mongodb.org/manual/reference/operator/query/ne/

CVE reference : Not defined

Creation date : 2014-10-17

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019957
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Generic PHP Remote File Include"; flow:to_server,established; content:"POST"; http_method; content:"allow_url_include"; http_uri; content:"safe_mode"; http_uri; content:"php|3a 2f 2f|input"; http_raw_uri; content:"<?php"; fast_pattern; http_client_body; content:"chmod 777"; http_client_body; classtype:attempted-user; sid:2019957; rev:3; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2014_12_17, updated_at 2019_10_07;)
` 

Name : **Generic PHP Remote File Include** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-12-17

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020323
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Heimdallbot Attack Tool Inbound"; flow:established,to_server; content:"Heimdallbot"; http_header; nocase; fast_pattern; pcre:"/^User-Agent\x3a[^\r\n]*?Heimdallbot/Hmi"; threshold: type limit, count 1, seconds 60, track by_src; classtype:web-application-attack; sid:2020323; rev:3; metadata:created_at 2015_01_28, updated_at 2019_10_07;)
` 

Name : **Heimdallbot Attack Tool Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-28

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017821
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER IIS ISN BackDoor Command Delete Log"; flow:established,to_server; content:"isn_logdel"; http_uri; nocase; fast_pattern; pcre:"/[?&]isn_logdel/Ui"; reference:url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html; classtype:trojan-activity; sid:2017821; rev:7; metadata:created_at 2013_12_09, updated_at 2019_10_07;)
` 

Name : **IIS ISN BackDoor Command Delete Log** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017822
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER IIS ISN BackDoor Command Get Logpath"; flow:established,to_server; content:"isn_logpath"; http_uri; nocase; fast_pattern; pcre:"/[?&]isn_logpath/Ui"; reference:url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html; classtype:trojan-activity; sid:2017822; rev:7; metadata:created_at 2013_12_09, updated_at 2019_10_07;)
` 

Name : **IIS ISN BackDoor Command Get Logpath** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.spiderlabs.com/2013/12/the-curious-case-of-the-malicious-iis-module.html

CVE reference : Not defined

Creation date : 2013-12-09

Last modified date : 2019-10-07

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022028
`alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt"; flow:established,to_server; content:" HTTP/1."; pcre:"/^[^\r\n]*?HTTP\/1(?:(?!\r?\n\r?\n)[\x20-\x7e\s]){1,500}\n[\x20-\x7e]{1,100}\x3a[\x20-\x7e]{0,500}\x28\x29\x20\x7b/s"; content:"|28 29 20 7b|"; fast_pattern; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2022028; rev:2; metadata:created_at 2015_11_03, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2014-6271 Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blogs.akamai.com/2014/09/environment-bashing.html

CVE reference : Not defined

Creation date : 2015-11-03

Last modified date : 2019-10-07

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022359
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WEBSHELL Linux/Torte Uploaded"; flow:established,to_server; content:"POST"; http_method; content:"JGVudiA9ICJYRFZTTl9TRVNTSU9OX0NPT0tJR"; http_client_body; fast_pattern; content:"eval(base64_decode($_REQUEST["; http_client_body; reference:url,blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html; classtype:attempted-admin; sid:2022359; rev:3; metadata:created_at 2016_01_13, updated_at 2019_10_07;)
` 

Name : **WEBSHELL Linux/Torte Uploaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html

CVE reference : Not defined

Creation date : 2016-01-13

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022348
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WEBSHELL JSP/Backdoor Shell Access"; flow:established,to_server; content:".war?cmd="; http_uri; fast_pattern; content:"&winurl="; http_uri; content:"&linurl="; http_uri; pcre:"/\.war\?cmd=[a-zA-Z0-9+/=]+&winurl=[a-zA-Z0-9+/=]*&linurl=[a-zA-Z0-9+/=]*/U"; reference:url,blog.malwaremustdie.org/2016/01/mmd-0049-2016-case-of-java-trojan.html; classtype:successful-admin; sid:2022348; rev:4; metadata:created_at 2016_01_11, updated_at 2019_10_07;)
` 

Name : **WEBSHELL JSP/Backdoor Shell Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,blog.malwaremustdie.org/2016/01/mmd-0049-2016-case-of-java-trojan.html

CVE reference : Not defined

Creation date : 2016-01-11

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022791
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3718 SSRF Inbound (mvg + fill + url)"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"fill"; http_client_body; content:"url("; http_client_body; distance:0; nocase; pcre:"/^\s*https?\x3a\/\//RPi"; classtype:web-application-attack; sid:2022791; rev:4; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3718 SSRF Inbound (mvg + fill + url)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022792
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3715 File Deletion Inbound (ephermeral:+ mvg)"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"ephemeral"; http_client_body; nocase; pcre:"/^\s*\x3a\s*[./]/RPi"; classtype:web-application-attack; sid:2022792; rev:4; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3715 File Deletion Inbound (ephermeral:+ mvg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022793
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3716 Move File Inbound (msl: + mvg)"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"msl"; http_client_body; nocase; pcre:"/^\s*\x3a\s*[./]/RPi"; classtype:web-application-attack; sid:2022793; rev:4; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3716 Move File Inbound (msl: + mvg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022794
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3717 Local File Read Inbound (label: + mvg)"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"label"; http_client_body; nocase; pcre:"/^\s*\x3a\s*\x40/RPi"; classtype:web-application-attack; sid:2022794; rev:4; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3717 Local File Read Inbound (label: + mvg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022789
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3714 Inbound (mvg)"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; pcre:"/https\x3a.+(?<!\x5c)(:[\x22\x27]|\\x2[27])\s*?[\x3b&\x7c><].*?(:[\x22\x27]|\\x2[27])/Psi"; classtype:web-application-attack; sid:2022789; rev:5; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3714 Inbound (mvg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022790
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER ImageMagick CVE-2016-3714 Inbound (svg)"; flow:established,to_server; content:"<svg "; http_client_body; nocase; fast_pattern; content:"xlink"; http_client_body; nocase; pcre:"/xlink\s*?\x3a\s*?href\s*?=\s*?(:[\x22\x27]|\\x2[27])https.+?&quot\s*?\x3b(?:\x7c|&(?:[gl]t|amp)\s*?\x3b)/Psi"; classtype:web-application-attack; sid:2022790; rev:5; metadata:created_at 2016_05_04, updated_at 2019_10_07;)
` 

Name : **ImageMagick CVE-2016-3714 Inbound (svg)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-05-04

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2014103
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Unusually Fast HTTP Requests With Referer Url Matching DoS Tool"; flow:to_server,established; content:"Referer|3a 20|"; http_header; content:"/slowhttptest/"; http_header; fast_pattern; pcre:"/Referer\x3a\x20[^\r\n]*\/slowhttptest\//Hi"; threshold: type both, track by_src, count 15, seconds 30; reference:url,community.qualys.com/blogs/securitylabs/2012/01/05/slow-read; classtype:web-application-activity; sid:2014103; rev:5; metadata:created_at 2012_01_09, updated_at 2019_10_07;)
` 

Name : **Unusually Fast HTTP Requests With Referer Url Matching DoS Tool** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,community.qualys.com/blogs/securitylabs/2012/01/05/slow-read

CVE reference : Not defined

Creation date : 2012-01-09

Last modified date : 2019-10-07

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022848
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2016-5118 Exploit MVG attempt M1"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"|20 27 7c|"; http_client_body; nocase; reference:url,seclists.org/oss-sec/2016/q2/432; reference:cve,2016-5118; classtype:trojan-activity; sid:2022848; rev:3; metadata:created_at 2016_06_01, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2016-5118 Exploit MVG attempt M1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/oss-sec/2016/q2/432|cve,2016-5118

CVE reference : Not defined

Creation date : 2016-06-01

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022849
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2016-5118 Exploit MVG attempt M2"; flow:established,to_server; content:"viewbox "; nocase; http_client_body; fast_pattern; content:"|20 22 7c|"; http_client_body; nocase; reference:url,seclists.org/oss-sec/2016/q2/432; reference:cve,2016-5118; classtype:trojan-activity; sid:2022849; rev:3; metadata:created_at 2016_06_01, updated_at 2019_10_07;)
` 

Name : **Possible CVE-2016-5118 Exploit MVG attempt M2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,seclists.org/oss-sec/2016/q2/432|cve,2016-5118

CVE reference : Not defined

Creation date : 2016-06-01

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022912
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Apache Continuum Arbitrary Command Execution"; flow:to_server,established; content:"POST"; http_method; content:"/saveInstallation.action"; http_uri; fast_pattern; content:"&installation.varValue="; http_client_body; content:"|25|60"; http_client_body; classtype:attempted-user; sid:2022912; rev:3; metadata:created_at 2016_06_22, updated_at 2019_10_07;)
` 

Name : **Apache Continuum Arbitrary Command Execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2016-06-22

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023231
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER HTTP Request to a *.33db9538.com domain - Anuna Checkin - Compromised PHP Site"; flow:to_server,established; content:"33db9538.com"; http_header; fast_pattern; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:bad-unknown; sid:2023231; rev:3; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.33db9538.com domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023232
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER HTTP Request to a *.9507c4e8.com domain - Anuna Checkin - Compromised PHP Site"; flow:to_server,established; content:"9507c4e8.com"; http_header; fast_pattern; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:bad-unknown; sid:2023232; rev:3; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.9507c4e8.com domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023233
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER HTTP Request to a *.e5b57288.com domain - Anuna Checkin - Compromised PHP Site"; flow:to_server,established; content:"e5b57288.com"; http_header; fast_pattern; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:bad-unknown; sid:2023233; rev:3; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.e5b57288.com domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2023234
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER HTTP Request to a *.54dfa1cb.com domain - Anuna Checkin - Compromised PHP Site"; flow:to_server,established; content:"54dfa1cb.com"; http_header; fast_pattern; reference:url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2; reference:url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code; classtype:bad-unknown; sid:2023234; rev:3; metadata:affected_product Apache_HTTP_server, affected_product PHP, attack_target Web_Server, deployment Datacenter, signature_severity Critical, created_at 2016_09_15, updated_at 2019_10_07;)
` 

Name : **HTTP Request to a *.54dfa1cb.com domain - Anuna Checkin - Compromised PHP Site** 

Attack target : Web_Server

Description : Alert is generated when obfuscated PHP code injected to web server makes a request to domains that have been observed to be hosting the Anuna payload. This is may be an indication that a backdoor is about to be download to the web server.

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : bad-unknown

URL reference : url,www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99&tabid=2|url,security.stackexchange.com/questions/47253/hacked-site-encrypted-code

CVE reference : Not defined

Creation date : 2016-09-15

Last modified date : 2019-10-07

Rev version : 3

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2020912
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)"; flow:established,to_server; content:"18446744073709551615"; http_header; fast_pattern; content:"Range|3a|"; nocase; http_header; pcre:"/^Range\x3a[^\r\n]*?18446744073709551615/Hmi"; reference:cve,2015-1635; classtype:web-application-attack; sid:2020912; rev:4; metadata:created_at 2015_04_15, updated_at 2019_10_07;)
` 

Name : **Possible IIS Integer Overflow DoS (CVE-2015-1635)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2015-1635

CVE reference : Not defined

Creation date : 2015-04-15

Last modified date : 2019-10-07

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010623
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Cisco IOS HTTP Server Exec Command Execution Attempt"; flow:to_server,established; content:"/level/15/exec/-/"; fast_pattern; nocase; http_uri; pcre:"/\x2Flevel\x2F15\x2Fexec\x2F\x2D\x2F[a-z]/Ui"; reference:url,doc.emergingthreats.net/2010623; classtype:web-application-attack; sid:2010623; rev:6; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **Cisco IOS HTTP Server Exec Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010623

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013049
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Binget PHP Library User Agent Inbound"; flow:established,to_server; content:"Binget/"; nocase; http_user_agent; depth:7; reference:url,www.bin-co.com/php/scripts/load/; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013049; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **Binget PHP Library User Agent Inbound** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013051
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER pxyscand Suspicious User Agent Inbound"; flow:established,to_server; content:"pxyscand/"; nocase; http_user_agent; depth:9; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013051; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **pxyscand Suspicious User Agent Inbound** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013053
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER PyCurl Suspicious User Agent Inbound"; flow:established,to_server; content:"User-Agent|3a 20|PyCurl"; nocase; http_header; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013053; rev:3; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **PyCurl Suspicious User Agent Inbound** 

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

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013057
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Inbound PHP User-Agent"; flow:established,to_server; content:"PHP/"; nocase; http_user_agent; depth:4; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013057; rev:4; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **Inbound PHP User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2019-10-11

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2013058
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Outbound PHP User-Agent"; flow:established,to_server; content:"PHP/"; nocase; http_user_agent; depth:4; reference:url,www.useragentstring.com/pages/useragentstring.php; classtype:attempted-recon; sid:2013058; rev:4; metadata:created_at 2011_06_17, updated_at 2019_10_11;)
` 

Name : **Outbound PHP User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.useragentstring.com/pages/useragentstring.php

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2019-10-11

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011174
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER SQL Injection Attempt (Agent CZxt2s)"; flow:to_server,established; content:"czxt2s"; nocase; http_user_agent; depth:6; isdataat:!1,relative; reference:url,doc.emergingthreats.net/2011174; classtype:web-application-attack; sid:2011174; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **SQL Injection Attempt (Agent CZxt2s)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2011174

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 5

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012286
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Automated Site Scanning for backupdata"; flow:established,to_server; content:"backupdata"; nocase; http_uri; content:"User-Agent|3a 20|Mozilla/4.0|0d 0a|"; http_header; classtype:attempted-recon; sid:2012286; rev:6; metadata:created_at 2011_02_04, updated_at 2019_10_11;)
` 

Name : **Automated Site Scanning for backupdata** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-04

Last modified date : 2019-10-11

Rev version : 6

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2012287
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Automated Site Scanning for backup_data"; flow:established,to_server; content:"backup_data"; nocase; http_uri; content:"User-Agent|3a 20|Mozilla/4.0|0d 0a|"; http_header; classtype:attempted-recon; sid:2012287; rev:5; metadata:created_at 2011_02_04, updated_at 2019_10_11;)
` 

Name : **Automated Site Scanning for backup_data** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-02-04

Last modified date : 2019-10-11

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011285
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (Casper-Like Jcomers Bot scan)"; flow:established,to_server; content:"Jcomers Bot"; nocase; http_user_agent; depth:11; metadata: former_category WEB_SERVER; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; reference:url,doc.emergingthreats.net/2011285; classtype:web-application-attack; sid:2011285; rev:7; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Bot Search RFI Scan (Casper-Like Jcomers Bot scan)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/|url,doc.emergingthreats.net/2011285

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009288
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Attack Tool Revolt Scanner"; flow:established,to_server; content:"revolt"; depth:6; http_user_agent; reference:url,www.Whitehatsecurityresponse.blogspot.com; reference:url,doc.emergingthreats.net/2009288; classtype:web-application-attack; sid:2009288; rev:58; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **Attack Tool Revolt Scanner** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.Whitehatsecurityresponse.blogspot.com|url,doc.emergingthreats.net/2009288

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 58

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2003616
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER DataCha0s Web Scanner/Robot"; flow:established,to_server; content:"DataCha0s"; nocase; depth:9; http_user_agent; reference:url,www.internetofficer.com/web-robot/datacha0s.html; reference:url,doc.emergingthreats.net/2003616; classtype:web-application-activity; sid:2003616; rev:40; metadata:created_at 2010_07_30, updated_at 2019_10_11;)
` 

Name : **DataCha0s Web Scanner/Robot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.internetofficer.com/web-robot/datacha0s.html|url,doc.emergingthreats.net/2003616

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-11

Rev version : 40

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009029
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER SQL Injection Attempt (Agent NV32ts)"; flow:to_server,established; content:"NV32ts"; depth:6; http_user_agent; reference:url,doc.emergingthreats.net/2009029; classtype:web-application-attack; sid:2009029; rev:8; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_10_15;)
` 

Name : **SQL Injection Attempt (Agent NV32ts)** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2009029

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-15

Rev version : 8

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019951
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER MorXploit Shell Command"; flow:established,to_server; content:"?cmd=ZXhpdA=="; http_uri; fast_pattern; content:"Mozilla 5"; http_user_agent; depth:9; reference:url,seclists.org/fulldisclosure/2014/Nov/78; classtype:bad-unknown; sid:2019951; rev:3; metadata:created_at 2014_12_16, updated_at 2019_10_16;)
` 

Name : **MorXploit Shell Command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,seclists.org/fulldisclosure/2014/Nov/78

CVE reference : Not defined

Creation date : 2014-12-16

Last modified date : 2019-10-16

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2028895
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible PHP Remote Code Execution CVE-2019-11043 PoC (Inbound)"; flow:established,to_server; content:"|25|OA"; http_uri; nocase; content:"=/bin/sh+-c+'"; http_uri; nocase; distance:0; fast_pattern; metadata: former_category WEB_SERVER; reference:url,github.com/neex/phuip-fpizdam; reference:url,github.com/vulhub/vulhub/tree/master/php/CVE-2019-11043; reference:cve,2019-11043; classtype:web-application-attack; sid:2028895; rev:2; metadata:affected_product PHP, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2019_10_23, updated_at 2019_10_23;)
` 

Name : **Possible PHP Remote Code Execution CVE-2019-11043 PoC (Inbound)** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : PHP

Alert Classtype : web-application-attack

URL reference : url,github.com/neex/phuip-fpizdam|url,github.com/vulhub/vulhub/tree/master/php/CVE-2019-11043|cve,2019-11043

CVE reference : Not defined

Creation date : 2019-10-23

Last modified date : 2019-10-23

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029008
`alert http $EXTERNAL_NET any -> any any (msg:"ET WEB_SERVER JAWS Webserver Unauthenticated Shell Command Execution"; flow:established,to_server; content:"GET"; http_method; content:"/shell?cd%20/tmp|3b|wget%20"; depth:24; http_raw_uri; fast_pattern; content:"Mozilla/5.0%20(Windows|3b|%20U|3b|%20Windows%20NT"; http_raw_header; metadata: former_category WEB_SERVER; reference:md5,a26f67a1d0a50af72c5fd9c94e9f5a1c; classtype:web-application-attack; sid:2029008; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2019_11_20, updated_at 2019_11_20;)
` 

Name : **JAWS Webserver Unauthenticated Shell Command Execution** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : md5,a26f67a1d0a50af72c5fd9c94e9f5a1c

CVE reference : Not defined

Creation date : 2019-11-20

Last modified date : 2019-11-20

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009363
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Suspicious Chmod Usage in URI (Inbound)"; flow:to_server,established; content:"chmod"; fast_pattern; nocase; http_uri; pcre:"/^(?:\+|\x2520|\x24IFS|\x252B|\s)+(?:x|[0-9]{3,4})/URi"; content:!"&launchmode="; http_uri; content:!"/chmod/"; http_uri; content:!"searchmod"; http_uri; metadata: former_category HUNTING; reference:url,doc.emergingthreats.net/2009363; classtype:attempted-admin; sid:2009363; rev:9; metadata:affected_product Linux, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2010_07_30, updated_at 2019_12_31;)
` 

Name : **Suspicious Chmod Usage in URI (Inbound)** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/2009363

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-12-31

Rev version : 8

Category : WEB_SERVER

Severity : Minor

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2017086
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER WebShell - GODSpy - MySQL"; flow:established,to_server; content:"dbhost="; http_client_body; content:"dbuser="; http_client_body; content:"dbpass="; http_client_body; classtype:trojan-activity; sid:2017086; rev:3; metadata:created_at 2013_07_02, updated_at 2020_02_06;)
` 

Name : **WebShell - GODSpy - MySQL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-02

Last modified date : 2020-02-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009670
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Nagios statuswml.cgi Remote Arbitrary Shell Command Injection attempt"; flow:to_server,established; content:"GET"; http_method; content:"/statuswml.cgi?"; http_uri; nocase; content:"ping"; http_uri; nocase; pcre:"/^\s*=\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[^\x26\x0D\x0A]*\x3B)/URi"; reference:bugtraq,35464; reference:url,doc.emergingthreats.net/2009670; classtype:web-application-attack; sid:2009670; rev:12; metadata:created_at 2010_07_30, updated_at 2020_02_10;)
` 

Name : **Nagios statuswml.cgi Remote Arbitrary Shell Command Injection attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,35464|url,doc.emergingthreats.net/2009670

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-10

Rev version : 12

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010379
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER JBOSS/JMX REMOTE WAR deployment attempt (POST)"; flow:established,to_server; content:"POST"; http_method; content:"/jmx-console/HtmlAdaptor"; http_uri; nocase; content:"action=invokeOp&name=jboss.deployment"; nocase; content:"flavor%253DURL%252Ctype%253DDeploymentScanner"; within:50; nocase; content:"=http%3A%2F%2F"; within:40; reference:url,www.notsosecure.com/folder2/2009/10/27/hacking-jboss-with-jmx-console/; reference:url,www.nruns.com/_downloads/Whitepaper-Hacking-jBoss-using-a-Browser.pdf; reference:url,doc.emergingthreats.net/2010379; classtype:web-application-attack; sid:2010379; rev:8; metadata:created_at 2010_07_30, updated_at 2020_02_10;)
` 

Name : **JBOSS/JMX REMOTE WAR deployment attempt (POST)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.notsosecure.com/folder2/2009/10/27/hacking-jboss-with-jmx-console/|url,www.nruns.com/_downloads/Whitepaper-Hacking-jBoss-using-a-Browser.pdf|url,doc.emergingthreats.net/2010379

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-10

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010380
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER JBOSS/JMX REMOTE WAR deployment attempt (GET)"; flow:established,to_server; content:"GET"; http_method; content:"/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.deployment"; http_uri; content:"DeploymentScanner"; http_uri; nocase; content:"methodName=addURL"; http_uri; nocase; content:"=http"; http_uri; nocase; reference:url,www.notsosecure.com/folder2/2009/10/27/hacking-jboss-with-jmx-console/; reference:url,www.nruns.com/_downloads/Whitepaper-Hacking-jBoss-using-a-Browser.pdf; reference:url,doc.emergingthreats.net/2010380; classtype:web-application-attack; sid:2010380; rev:8; metadata:created_at 2010_07_30, updated_at 2020_02_10;)
` 

Name : **JBOSS/JMX REMOTE WAR deployment attempt (GET)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.notsosecure.com/folder2/2009/10/27/hacking-jboss-with-jmx-console/|url,www.nruns.com/_downloads/Whitepaper-Hacking-jBoss-using-a-Browser.pdf|url,doc.emergingthreats.net/2010380

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-10

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2008171
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HP OpenView Network Node Manager CGI Directory Traversal"; flow:to_server,established; content:"GET"; http_method; content:"/OvCgi/"; nocase; http_uri;content:"/OpenView5.exe?"; nocase; distance:0; fast_pattern; http_uri; content:"Action=../../"; nocase; distance:0; http_uri; http_protocol; content:"HTTP/1."; reference:bugtraq,28745; reference:cve,CVE-2008-0068; reference:url,aluigi.altervista.org/adv/closedviewx-adv.txt; reference:url,doc.emergingthreats.net/2008171; classtype:web-application-attack; sid:2008171; rev:11; metadata:created_at 2010_07_30, updated_at 2020_02_24;)
` 

Name : **HP OpenView Network Node Manager CGI Directory Traversal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,28745|cve,CVE-2008-0068|url,aluigi.altervista.org/adv/closedviewx-adv.txt|url,doc.emergingthreats.net/2008171

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-24

Rev version : 11

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010513
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET 1024: (msg:"ET WEB_SERVER Possible HTTP 401 XSS Attempt (Local Source)"; flow:from_server,established; content:"401"; http_stat_code; content:"Unauthorized"; nocase; http_stat_msg; file_data; content:"<script"; nocase; depth:280; fast_pattern; threshold:type threshold,track by_src,count 10,seconds 60; reference:url,doc.emergingthreats.net/2010513; classtype:web-application-attack; sid:2010513; rev:7; metadata:created_at 2010_07_30, updated_at 2020_02_25;)
` 

Name : **Possible HTTP 401 XSS Attempt (Local Source)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010513

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-25

Rev version : 7

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010698
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible D-Link Router HNAP Protocol Security Bypass Attempt"; flow:established,to_server; urilen:7; content:"POST"; http_method; content:"/HNAP1/"; nocase; isdataat:!1,relative; fast_pattern; http_uri; content:"SOAPAction|3a 20|"; nocase; http_header; content:"/HNAP1/"; http_header; distance:0; pcre:"/^(?:set|get)/HRi"; content:"DeviceSettings"; within:14; http_header; reference:url,www.securityfocus.com/bid/37690; reference:url,doc.emergingthreats.net/2010698; classtype:web-application-attack; sid:2010698; rev:5; metadata:created_at 2010_07_30, updated_at 2020_02_25;)
` 

Name : **Possible D-Link Router HNAP Protocol Security Bypass Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/37690|url,doc.emergingthreats.net/2010698

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-25

Rev version : 5

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010864
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER HP OpenView /OvCgi/Toolbar.exe Accept Language Heap Buffer Overflow Attempt"; flow:established,to_server; content:"POST"; http_method; content:"/OvCgi/Toolbar.exe"; nocase; fast_pattern; http_uri; content:"Accept-Language|3a 20|"; nocase; isdataat:1350,relative; http_header; content:!"|0A|"; within:1350; http_header; content:"Content-Length|3a|"; distance:0; http_header; reference:cve,2009-0921; reference:url,doc.emergingthreats.net/2010864; classtype:web-application-attack; sid:2010864; rev:9; metadata:created_at 2010_07_30, updated_at 2020_02_25;)
` 

Name : **HP OpenView /OvCgi/Toolbar.exe Accept Language Heap Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2009-0921|url,doc.emergingthreats.net/2010864

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-02-25

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022260
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Possible Darkleech C2"; flow:established,to_server; content:"/blog/?"; http_uri; depth:7; fast_pattern; content:"&utm_source="; http_uri; distance:0; pcre:"/^\/blog\/\?[a-z]{3,20}+\&utm_source=\d+\x3a\d+\x3a\d+$/U"; pcre:"/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/W"; http_header_names; content:!"Referer|0d 0a|"; metadata: former_category WEB_SERVER; reference:url,blog.sucuri.net/2015/12/evolution-of-pseudo-darkleech.html; classtype:trojan-activity; sid:2022260; rev:3; metadata:created_at 2015_12_14, updated_at 2020_02_28;)
` 

Name : **Possible Darkleech C2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : url,blog.sucuri.net/2015/12/evolution-of-pseudo-darkleech.html

CVE reference : Not defined

Creation date : 2015-12-14

Last modified date : 2020-02-28

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019749
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER FOX-SRT - Backdoor - CryptoPHP Shell C2 POST (fsockopen)"; flow:established,to_server; content:"POST"; http_method; content:"serverKey="; fast_pattern; content:"data="; content:"key="; http_header_names; content:!"Referer|0d 0a|"; content:!"User-Agent"; content:!"Cookie|0d 0a|"; http_connection; content:"close"; depth:5; isdataat:!1,relative; http_content_type; content:"application/x-www-form-urlencoded"; depth:33; threshold: type limit, track by_src, count 1, seconds 600; metadata: former_category WEB_SERVER; reference:url,blog.fox-it.com/2014/11/18/cryptophp-analysis-of-a-hidden-threat-inside-popular-content-management-systems/; classtype:trojan-activity; sid:2019749; rev:3; metadata:created_at 2014_11_20, updated_at 2020_03_03;)
` 

Name : **FOX-SRT - Backdoor - CryptoPHP Shell C2 POST (fsockopen)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : url,blog.fox-it.com/2014/11/18/cryptophp-analysis-of-a-hidden-threat-inside-popular-content-management-systems/

CVE reference : Not defined

Creation date : 2014-11-20

Last modified date : 2020-03-03

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2022295
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER WeBaCoo Web Backdoor Detected"; flow:to_server,established; content:"GET"; http_method; content:"cm="; http_cookie; content:"cn=M-cookie|3b|"; fast_pattern; http_cookie; content:"cp="; http_cookie; reference:url,panagioto.com/webacoo-backdoor-detection; classtype:web-application-activity; sid:2022295; rev:4; metadata:created_at 2015_12_21, updated_at 2020_03_05;)
` 

Name : **WeBaCoo Web Backdoor Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,panagioto.com/webacoo-backdoor-detection

CVE reference : Not defined

Creation date : 2015-12-21

Last modified date : 2020-03-05

Rev version : 4

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2019748
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER FOX-SRT - Backdoor - CryptoPHP Shell C2 POST"; flow:established,to_server; content:"POST"; http_method; content:"Content-Disposition|3a 20|form-data|3b 20|name=|22|serverKey|22|"; http_client_body; fast_pattern; content:"Content-Disposition|3a 20|form-data|3b 20|name=|22|data|22|"; http_client_body; content:"Content-Disposition|3a 20|form-data|3b 20|name=|22|key|22|"; http_client_body; http_header_names; content:!"Referer|0d 0a|"; content:!"User-Agent"; content:!"Cookie|0d 0a|"; threshold: type limit, track by_src, count 1, seconds 600; metadata: former_category WEB_SERVER; reference:url,blog.fox-it.com/2014/11/18/cryptophp-analysis-of-a-hidden-threat-inside-popular-content-management-systems/; classtype:trojan-activity; sid:2019748; rev:3; metadata:created_at 2014_11_20, updated_at 2020_03_06;)
` 

Name : **FOX-SRT - Backdoor - CryptoPHP Shell C2 POST** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : url,blog.fox-it.com/2014/11/18/cryptophp-analysis-of-a-hidden-threat-inside-popular-content-management-systems/

CVE reference : Not defined

Creation date : 2014-11-20

Last modified date : 2020-03-06

Rev version : 3

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2015625
`alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Magento XMLRPC-Exploit Attempt"; flow:established,to_server; content:"POST"; nocase; http_method; content:"/api/xmlrpc"; http_uri; content:"file|3a 2f 2f 2f|"; http_client_body; fast_pattern; reference:url,www.magentocommerce.com/blog/comments/important-security-update-zend-platform-vulnerability/; reference:url,www.magentocommerce.com/blog/update-zend-framework-vulnerability-security-update; reference:url,www.exploit-db.com/exploits/19793/; classtype:web-application-attack; sid:2015625; rev:3; metadata:created_at 2012_08_15, updated_at 2020_03_09;)
` 

Name : **Magento XMLRPC-Exploit Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.magentocommerce.com/blog/comments/important-security-update-zend-platform-vulnerability/|url,www.magentocommerce.com/blog/update-zend-framework-vulnerability-security-update|url,www.exploit-db.com/exploits/19793/

CVE reference : Not defined

Creation date : 2012-08-15

Last modified date : 2020-03-09

Rev version : 2

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010964
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER SHOW CHARACTER SET SQL Injection Attempt in URI"; flow:established,to_server; content:"SHOW"; http_uri; nocase; content:"CHARACTER"; http_uri; nocase; distance:0; content:"SET"; nocase; distance:0; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,dev.mysql.com/doc/refman/5.0/en/show-character-set.html; reference:url,doc.emergingthreats.net/2010964; classtype:web-application-attack; sid:2010964; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2020_03_13;)
` 

Name : **SHOW CHARACTER SET SQL Injection Attempt in URI** 

Attack target : Web_Server

Description : SQL injection (SQLi) attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the database, recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. Common actions taken by successful attackers are to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

SQLi vulnerabilities are common, and have enjoyed the top ranks of the OWASP top 10 for a number of years. Furthermore, it is very common with PHP and ASP applications due to the prevalence of older functional interfaces. Due to the nature of programmatic interfaces available, J2EE and ASP.NET applications are less likely to have easily exploited SQL injections.

When these signatures generate alerts, it indicates an attacker is probing for a web application that is vulnerable to SQLi. It is a common practice for attackers to scan en masse for these vulnerabilities and then return with more sophisticated attacks when the web application returns a SQL error message that indicates it is vulnerable. A typical next step for an attacker would be to inject malicious redirects, or reset an administrative password.

To aid in validating whether or not an SQL Injection alert is a valid hit, you can take the following steps:
Is the signature triggering on a web application in your datacenter?  These signatures are not typically deployed for inspecting outbound client traffic to the internet. 
Does the alert match the web application deployed (if not generic SQL detection?) Sometimes due to broad vulnerabilities that might be perfectly fine behavior in certain apps they can impact other applications if misapplied.
Is the attack source known in ET Intelligence?  Often times well known scanners, brute forcers, and other malicious actors will have reputation in ET Intelligence which can help to determine if the behavior is previously known to be malicious.

Tags : SQL_Injection

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,dev.mysql.com/doc/refman/5.0/en/show-character-set.html|url,doc.emergingthreats.net/2010964

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-03-13

Rev version : 6

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010863
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER LANDesk Command Injection Attempt"; flow:established,to_server; content:"POST"; http_method; content:"/gsb/datetime.php"; http_uri; nocase; content:"delBackupName"; nocase; http_client_body; content:"backupRestoreFormSubmitted"; distance:0; nocase; http_client_body; reference:url,www.coresecurity.com/content/landesk-csrf-vulnerability; reference:cve,2010-0369; reference:url,doc.emergingthreats.net/2010863; classtype:web-application-attack; sid:2010863; rev:8; metadata:created_at 2010_07_30, updated_at 2020_03_13;)
` 

Name : **LANDesk Command Injection Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.coresecurity.com/content/landesk-csrf-vulnerability|cve,2010-0369|url,doc.emergingthreats.net/2010863

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-03-13

Rev version : 8

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010704
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow Attempt"; flow:established,to_server; content:"GET"; http_method; nocase; content:"/OvCgi/ovalarm.exe"; http_uri; nocase; fast_pattern; content:"OVABverbose="; http_uri; nocase; distance:0; pcre:"/^(1|on|true)/URi"; http_accept_lang; isdataat:100,relative; reference:cve,2009-4179; reference:url,doc.emergingthreats.net/2010704; classtype:web-application-attack; sid:2010704; rev:9; metadata:created_at 2010_07_30, updated_at 2020_03_13;)
` 

Name : **Possible HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2009-4179|url,doc.emergingthreats.net/2010704

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-03-13

Rev version : 9

Category : WEB_SERVER

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010457
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco Adaptive Security Appliance Web VPN FTP or CIFS Authentication Form Phishing Attempt"; flow:established,to_server; content:"+CSCOE+/files/browse.html"; nocase; http_uri; fast_pattern; content:"code=init"; http_uri; nocase; distance:0; content:"path=ftp"; http_uri; nocase; distance:0; reference:url,www.securityfocus.com/bid/35475/info; reference:cve,2009-1203; reference:url,doc.emergingthreats.net/2010457; classtype:attempted-user; sid:2010457; rev:8; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2010_07_30, updated_at 2020_03_13;)
` 

Name : **Possible Cisco Adaptive Security Appliance Web VPN FTP or CIFS Authentication Form Phishing Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,www.securityfocus.com/bid/35475/info|cve,2009-1203|url,doc.emergingthreats.net/2010457

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-03-13

Rev version : 8

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029860
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO 2.6 Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"WebShellOrb 2.6</title>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029860; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **WSO 2.6 Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029862
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO 2.5 Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"WSO 2.5</title>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029862; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **WSO 2.5 Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029864
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER X-Sec Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>X-Sec Shell V."; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029864; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **X-Sec Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029866
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER ALFA TEaM Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"ALFA TEaM Shell - v"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029866; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **ALFA TEaM Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029868
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO 4.2.5 Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"WSO 4.2.5</title>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029868; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **WSO 4.2.5 Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029870
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO 4.2.6 Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"WSO 4.2.6</title>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029870; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **WSO 4.2.6 Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029872
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Kageyama Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<H1><center>Shell Kageyama</center></H1>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029872; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **Kageyama Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029874
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic WSO Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<span>Uname:<br>User:<br>Php:<br>Hdd:<br>Cwd:</span></td><td><nobr>"; nocase; fast_pattern; content:"<span>Group:</span>"; nocase; distance:0; content:"<span>Safe mode:</span>"; nocase; distance:0; content:"<span>Datetime:</span>"; nocase; distance:0; content:"<span>Free:</span>"; nocase; distance:0; content:"<span>Server IP:</span>"; nocase; distance:0; content:"<span>Client IP:</span>"; nocase; distance:0; content:">Self remove</a>"; nocase; distance:0; content:"<h1>File manager</h1>"; nocase; distance:0; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029874; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **Generic WSO Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029876
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER MINI MO Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>MINI MO Shell</title>"; nocase; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029876; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_10, updated_at 2020_04_10;)
` 

Name : **MINI MO Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : This alert indicates that a machine accessed a webshell on a webhost defined in $HTTP_SERVERS 


Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-10

Last modified date : 2020-04-10

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029883
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic WSO Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<form method=post>Password: <input type=password name=pass><input type=submit value='>>'></form>"; fast_pattern; classtype:web-application-attack; sid:2029883; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Generic WSO Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029885
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic WSO Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<form   method=|20 22|post|22 20|action=|20 22 22|> <input type=|22|input|22 20|name =|22|f_pp|22 20|value=|20 22 22|/><input type=|20 22|submit|22 20|value="; fast_pattern; classtype:web-application-attack; sid:2029885; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Generic WSO Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029887
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Anonymous Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>AnonyMous SHell</title>"; nocase; fast_pattern; content:"id=|22|pageheading|22|>AnonyMous SHell"; nocase; distance:0; classtype:web-application-attack; sid:2029887; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Anonymous Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029889
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Mini Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<tr><td>Current Path : <a href=|22|?path=/"; nocase; content:"<tr class=|22|first|22|>"; nocase; distance:0; content:"<td><center>File/Folder Name</center></td>"; nocase; distance:0; content:"<td><center>Size</center></td>"; nocase; distance:0; content:"<td><center>Permissions</center></td>"; nocase; distance:0; content:"<td><center>Options</center></td>"; nocase; distance:0; content:"<td><center><form method=|22|POST|22 20|action=|22|?option&path="; nocase; distance:0; fast_pattern; content:"<td><a href=|22|?filesrc="; nocase; distance:0; content:"<option value=|22|delete|22|>Delete</option>"; nocase; distance:0; content:"<option value=|22|chmod|22|>Chmod</option>"; nocase; distance:0; content:"<option value=|22|rename|22|>Rename</option>"; nocase; distance:0; content:"<option value=|22|edit|22|>Edit</option>"; nocase; distance:0; classtype:web-application-attack; sid:2029889; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Generic Mini Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029891
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<form method=post>password<br><input type=password name=pass style=|22|background-color:whitesmoke|3b|border:1px solid #fff|3b|outline:none|3b|' required>"; content:"<input type=submit name=|22|watching|22 20|value=|22|submit|22 20|style=|22|border:none|3b|background-color:#56ad15|3b|color:#fff|3b|cursor:pointer|3b 22|></form>"; distance:0; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029891; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_13, updated_at 2020_04_13;)
` 

Name : **Generic Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-13

Last modified date : 2020-04-13

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029901
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<form method=post>Password<br><input type=password name=pass style='background-color:whitesmoke|3b|border:1px solid #FFF|3b|outline:none|3b|' required>"; content:"<input type=submit name='watching' value='submit' style='border:none|3b|background-color:#56AD15|3b|color:#fff|3b|cursor:pointer|3b|'></form>"; distance:0; fast_pattern; classtype:web-application-attack; sid:2029901; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_14, updated_at 2020_04_14;)
` 

Name : **Generic Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-14

Last modified date : 2020-04-14

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029903
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<form action=|22 22 20|method=|22|post|22|><input type=|22|text|22 20|name=|22|_nv|22|><input type=|22|submit|22 20|value=|22|>>|22|></form>"; distance:0; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029903; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_14, updated_at 2020_04_14;)
` 

Name : **WSO Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-14

Last modified date : 2020-04-14

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029905
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Leaf PHPMailer Accessed on Internal Server"; flow:established,to_client; file_data; content:"<title>Leaf PHPMailer"; fast_pattern; content:"<li>[-email-] : <b>Reciver Email"; content:"<li>[-emailuser-] : <b>Email User"; classtype:web-application-attack; sid:2029905; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2020_04_14, updated_at 2020_04_14;)
` 

Name : **Leaf PHPMailer Accessed on Internal Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-14

Last modified date : 2020-04-14

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029907
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Owl PHPMailer Accessed on Internal Server"; flow:established,to_client; file_data; content:"<title>Owl PHPMailer"; fast_pattern; content:"function stopSending()"; content:"function startSending()"; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029907; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Major, created_at 2020_04_14, updated_at 2020_04_14;)
` 

Name : **Owl PHPMailer Accessed on Internal Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-14

Last modified date : 2020-04-14

Rev version : 2

Category : WEB_SERVER

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029909
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Password Prompt Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<input type=password name=pass style='background-color:whitesmoke|3b|border:1px solid #FFF|3b|outline:none|3b|' required>"; content:"<input type=submit name='watching' value='>>' style="; distance:0; fast_pattern; classtype:web-application-attack; sid:2029909; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_14, updated_at 2020_04_14;)
` 

Name : **Generic Webshell Password Prompt Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-14

Last modified date : 2020-04-14

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029915
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER 16Shop Phishing Kit Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>16SHOP"; fast_pattern; content:"<label>Public Key"; distance:0; content:"<label>Password"; distance:0; classtype:web-application-attack; sid:2029915; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_15, updated_at 2020_04_15;)
` 

Name : **16Shop Phishing Kit Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-15

Last modified date : 2020-04-15

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029917
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<font><font>file Manager</font></font>"; nocase; distance:0; content:"<font><font>Back Connect"; nocase; distance:0; content:"<font><font>CgiShell</font></font>"; nocase; distance:0; content:"<font><font>Symlink</font></font>"; nocase; distance:0; content:"Mailer</font></font>"; nocase; distance:0; content:"<font><font>Auto r00t</font></font>"; nocase; distance:0; content:"<font><font>Upload</font></font>"; nocase; distance:0; content:"Exploiter & scan Tools</font></font>"; nocase; distance:0; fast_pattern; content:"<font><font>Self remove</font></font>"; nocase; distance:0; classtype:web-application-attack; sid:2029917; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_15, updated_at 2020_04_15;)
` 

Name : **Generic Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-15

Last modified date : 2020-04-15

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029919
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<meta name=|22|description|22 20|content=|22|This Mini Shell"; nocase; content:"<meta name=|22|author|22 20|content=|22|An0n 3xPloiTeR"; fast_pattern; distance:0; nocase; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029919; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_15, updated_at 2020_04_15;)
` 

Name : **Generic Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-15

Last modified date : 2020-04-15

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029937
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>DRIV3R KR PRIV8 MAILER"; fast_pattern; nocase; classtype:web-application-attack; sid:2029937; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029935
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER WSO 2.6 Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"WSO 2.6</title>"; nocase; fast_pattern; classtype:web-application-attack; sid:2029935; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **WSO 2.6 Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029939
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic Webshell Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<meta name=|22|Description|22 20|content=|22|Mr.Rm19"; nocase; content:">Time On Server : <font color="; nocase; distance:0; content:">Server IP : <font color="; nocase; distance:0; content:">Current Dir : </font><a href="; nocase; distance:0; content:">Mass Deface</a>"; nocase; distance:0; fast_pattern; classtype:web-application-attack; sid:2029939; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic Webshell Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029941
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>|20 7c 20|Log In|20 7c 20|Power Mailer Inbox"; nocase; content:"</a>Welcome To Power Mailer Inbox"; nocase; distance:0; fast_pattern; classtype:web-application-attack; sid:2029941; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029943
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>F. Mortolino</title>"; nocase; content:"MortoLino - mode*SPAMMER"; nocase; distance:0; fast_pattern; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029943; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029945
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>GwEx Mailer"; nocase; fast_pattern; content:">GwEx Mailer </font>"; nocase; distance:0; classtype:web-application-attack; sid:2029945; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029947
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>W0rmVps PRIV8 MAILER"; nocase; fast_pattern; classtype:web-application-attack; sid:2029947; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_20;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-20

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029949
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>SMTP Mailer</title>"; nocase; fast_pattern; content:">Inbox SMTP Mailer</div>"; nocase; distance:0; metadata: former_category WEB_SERVER; classtype:web-application-attack; sid:2029949; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2029951
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET WEB_SERVER Generic PHP Mailer Accessed on Internal Compromised Server"; flow:established,to_client; file_data; content:"<title>Priv8 Mailer Inbox"; nocase; fast_pattern; content:"document.getElementById(|22|xmailer"; nocase; distance:0; classtype:web-application-attack; sid:2029951; rev:1; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Perimeter, signature_severity Critical, created_at 2020_04_17, updated_at 2020_04_17;)
` 

Name : **Generic PHP Mailer Accessed on Internal Compromised Server** 

Attack target : Web_Server

Description : Not defined

Tags : Not defined

Affected products : Web_Server_Applications

Alert Classtype : web-application-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2020-04-17

Last modified date : 2020-04-17

Rev version : 2

Category : WEB_SERVER

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

