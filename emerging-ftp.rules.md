# 2010732
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP SITE command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"SITE"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010732; classtype:attempted-recon; sid:2010732; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP SITE command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010732

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010733
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP RMDIR command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"RMDIR"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010733; classtype:attempted-recon; sid:2010733; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP RMDIR command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010733

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010734
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP MKDIR command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"MKDIR"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010734; classtype:attempted-recon; sid:2010734; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP MKDIR command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010734

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010735
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP PWD command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"PWD"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010735; classtype:attempted-recon; sid:2010735; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP PWD command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010735

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010736
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP RETR command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"RETR"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010736; classtype:attempted-recon; sid:2010736; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP RETR command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010736

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010737
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP NLST command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"NLST"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010737; classtype:attempted-recon; sid:2010737; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP NLST command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010737

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010738
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP RNTO command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"RNTO"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010738; classtype:attempted-recon; sid:2010738; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP RNTO command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010738

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010739
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP RNFR command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"RNFR"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010739; classtype:attempted-recon; sid:2010739; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP RNFR command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010739

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010740
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP STOR command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"STOR"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010740; classtype:attempted-recon; sid:2010740; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP STOR command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010740

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002851
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP HP-UX LIST command without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:"LIST "; nocase; depth:5; reference:cve,2005-3296; reference:bugtraq,15138; reference:url,doc.emergingthreats.net/bin/view/Main/2002851; classtype:attempted-recon; sid:2002851; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HP-UX LIST command without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : cve,2005-3296|bugtraq,15138|url,doc.emergingthreats.net/bin/view/Main/2002851

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009981
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username SELECT FROM SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"SELECT"; within:200; nocase; content:"FROM"; distance:0; nocase; pcre:"/SELECT.+FROM/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2009981; classtype:attempted-user; sid:2009981; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username SELECT FROM SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2009981

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009982
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username DELETE FROM SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"DELETE"; within:200; nocase; content:"FROM"; distance:0; nocase; pcre:"/DELETE.+FROM/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2009982; classtype:attempted-user; sid:2009982; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username DELETE FROM SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2009982

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009983
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username INSERT INTO SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"INSERT"; within:200; nocase; content:"INTO"; distance:0; nocase; pcre:"/INSERT.+INTO/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2009983; classtype:attempted-user; sid:2009983; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username INSERT INTO SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2009983

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009984
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username UPDATE SET SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"UPDATE"; within:200; nocase; content:"SET"; distance:0; nocase; pcre:"/UPDATE.+SET/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2009984; classtype:attempted-user; sid:2009984; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username UPDATE SET SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2009984

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2009985
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username UNION SELECT SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"UNION"; within:200; nocase; content:"SELECT"; distance:0; nocase; pcre:"/UNION.+SELECT/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2009985; classtype:attempted-user; sid:2009985; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username UNION SELECT SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,en.wikipedia.org/wiki/SQL_injection|url,doc.emergingthreats.net/2009985

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010081
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username INTO OUTFILE SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"INTO"; within:200; nocase; content:"OUTFILE"; distance:0; nocase; pcre:"/INTO.+OUTFILE/i"; reference:url,www.milw0rm.com/papers/372; reference:url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection; reference:url,websec.wordpress.com/2007/11/17/mysql-into-outfile/; reference:url,doc.emergingthreats.net/2010081; classtype:attempted-user; sid:2010081; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Possible FTP Daemon Username INTO OUTFILE SQL Injection Attempt** 

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

Alert Classtype : attempted-user

URL reference : url,www.milw0rm.com/papers/372|url,www.greensql.net/publications/backdoor-webserver-using-mysql-sql-injection|url,websec.wordpress.com/2007/11/17/mysql-into-outfile/|url,doc.emergingthreats.net/2010081

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : FTP

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101992
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP LIST directory traversal attempt"; flow:to_server,established; content:"LIST"; nocase; content:".."; distance:1; content:".."; distance:1; reference:bugtraq,2618; reference:cve,2001-0680; reference:cve,2002-1054; reference:nessus,11112; classtype:protocol-command-decode; sid:2101992; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **LIST directory traversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,2618|cve,2001-0680|cve,2002-1054|nessus,11112

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101971
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE EXEC format string attempt"; flow:to_server,established; content:"SITE"; nocase; content:"EXEC"; distance:0; nocase; pcre:"/^SITE\s+EXEC\s[^\n]*?%[^\n]*?%/smi"; classtype:bad-unknown; sid:2101971; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE EXEC format string attempt** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101972
`alert ftp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP PASS overflow attempt"; flow:to_server,established,no_stream; content:"PASS"; nocase; isdataat:100,relative; pcre:"/^PASS\s[^\n]{100}/smi"; reference:bugtraq,10078; reference:bugtraq,10720; reference:bugtraq,1690; reference:bugtraq,3884; reference:bugtraq,8601; reference:bugtraq,9285; reference:cve,1999-1519; reference:cve,1999-1539; reference:cve,2000-1035; reference:cve,2002-0126; reference:cve,2002-0895; classtype:attempted-admin; sid:2101972; rev:18; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PASS overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10078|bugtraq,10720|bugtraq,1690|bugtraq,3884|bugtraq,8601|bugtraq,9285|cve,1999-1519|cve,1999-1539|cve,2000-1035|cve,2002-0126|cve,2002-0895

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 18

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101973
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP MKD overflow attempt"; flow:to_server,established; content:"MKD"; nocase; isdataat:100,relative; pcre:"/^MKD\s[^\n]{100}/smi"; reference:bugtraq,612; reference:bugtraq,7278; reference:bugtraq,9872; reference:cve,1999-0911; reference:nessus,12108; classtype:attempted-admin; sid:2101973; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MKD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,612|bugtraq,7278|bugtraq,9872|cve,1999-0911|nessus,12108

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101974
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP REST overflow attempt"; flow:to_server,established; content:"REST"; nocase; isdataat:100,relative; pcre:"/^REST\s[^\n]{100}/smi"; reference:bugtraq,2972; reference:cve,2001-0826; classtype:attempted-admin; sid:2101974; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **REST overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2972|cve,2001-0826

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101975
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP DELE overflow attempt"; flow:to_server,established; content:"DELE"; nocase; isdataat:100,relative; pcre:"/^DELE\s[^\n]{100}/smi"; reference:bugtraq,2972; reference:cve,2001-0826; reference:cve,2001-1021; classtype:attempted-admin; sid:2101975; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **DELE overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2972|cve,2001-0826|cve,2001-1021

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101976
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP RMD overflow attempt"; flow:to_server,established; content:"RMD"; nocase; isdataat:100,relative; pcre:"/^RMD\s[^\n]{100}/smi"; reference:bugtraq,2972; reference:cve,2000-0133; reference:cve,2001-0826; reference:cve,2001-1021; classtype:attempted-admin; sid:2101976; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RMD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2972|cve,2000-0133|cve,2001-0826|cve,2001-1021

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101942
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RMDIR overflow attempt"; flow:to_server,established; content:"RMDIR"; nocase; isdataat:100,relative; pcre:"/^RMDIR\s[^\n]{100}/smi"; reference:bugtraq,819; classtype:attempted-admin; sid:2101942; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RMDIR overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,819

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101920
`alert ftp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP SITE NEWER overflow attempt"; flow:to_server,established; content:"SITE"; nocase; content:"NEWER"; distance:0; nocase; isdataat:100,relative; pcre:"/^SITE\s+NEWER\s[^\n]{100}/smi"; reference:bugtraq,229; reference:cve,1999-0800; classtype:attempted-admin; sid:2101920; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE NEWER overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,229|cve,1999-0800

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101921
`alert ftp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP SITE ZIPCHK overflow attempt"; flow:to_server,established; content:"SITE"; nocase; content:"ZIPCHK"; distance:1; nocase; isdataat:100,relative; pcre:"/^SITE\s+ZIPCHK\s[^\n]{100}/smi"; reference:cve,2000-0040; classtype:attempted-admin; sid:2101921; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE ZIPCHK overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,2000-0040

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100334
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP .forward"; flow:to_server,established; content:".forward"; reference:arachnids,319; classtype:suspicious-filename-detect; sid:2100334; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **.forward** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : arachnids,319

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100335
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP .rhosts"; flow:to_server,established; content:".rhosts"; reference:arachnids,328; classtype:suspicious-filename-detect; sid:2100335; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **.rhosts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : arachnids,328

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100144
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP ADMw0rm ftp login attempt"; flow:to_server,established; content:"USER"; nocase; content:"w0rm"; distance:1; nocase; pcre:"/^USER\s+w0rm/smi"; reference:arachnids,01; classtype:suspicious-login; sid:2100144; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ADMw0rm ftp login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,01

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102449
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP ALLO overflow attempt"; flow:to_server,established; content:"ALLO"; nocase; isdataat:100,relative; pcre:"/^ALLO\s[^\n]{100}/smi"; reference:bugtraq,9953; classtype:attempted-admin; sid:2102449; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ALLO overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9953

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100337
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP CEL overflow attempt"; flow:to_server,established; content:"CEL"; nocase; isdataat:100,relative; pcre:"/^CEL\s[^\n]{100}/smi"; reference:arachnids,257; reference:bugtraq,679; reference:cve,1999-0789; reference:nessus,10009; classtype:attempted-admin; sid:2100337; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CEL overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,257|bugtraq,679|cve,1999-0789|nessus,10009

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101621
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP CMD overflow attempt"; flow:to_server,established; content:"CMD"; nocase; isdataat:100,relative; pcre:"/^CMD\s[^\n]{100}/smi"; classtype:attempted-admin; sid:2101621; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CMD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101919
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP CWD overflow attempt"; flow:to_server,established; content:"CWD"; nocase; isdataat:100,relative; pcre:"/^CWD\s[^\n]{100}/smi"; reference:bugtraq,11069; reference:bugtraq,1227; reference:bugtraq,1690; reference:bugtraq,6869; reference:bugtraq,7251; reference:bugtraq,7950; reference:cve,1999-0219; reference:cve,1999-1058; reference:cve,1999-1510; reference:cve,2000-1035; reference:cve,2000-1194; reference:cve,2001-0781; reference:cve,2002-0126; reference:cve,2002-0405; classtype:attempted-admin; sid:2101919; rev:24; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11069|bugtraq,1227|bugtraq,1690|bugtraq,6869|bugtraq,7251|bugtraq,7950|cve,1999-0219|cve,1999-1058|cve,1999-1510|cve,2000-1035|cve,2000-1194|cve,2001-0781|cve,2002-0126|cve,2002-0405

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 24

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101888
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE CPWD overflow attempt"; flow:established,to_server; content:"SITE"; nocase; content:"CPWD"; distance:0; nocase; isdataat:100,relative; pcre:"/^SITE\s+CPWD\s[^\n]{100}/smi"; reference:bugtraq,5427; reference:cve,2002-0826; classtype:misc-attack; sid:2101888; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE CPWD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,5427|cve,2002-0826

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101864
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE NEWER attempt"; flow:to_server,established; content:"SITE"; nocase; content:"NEWER"; distance:1; nocase; pcre:"/^SITE\s+NEWER/smi"; reference:cve,1999-0880; reference:nessus,10319; classtype:attempted-dos; sid:2101864; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE NEWER attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : cve,1999-0880|nessus,10319

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101777
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any  (msg:"GPL FTP STAT * dos attempt"; flow:to_server,established; content:"STAT"; nocase; pcre:"/^STAT\s+[^\n]*\x2a/smi"; metadata: former_category FTP; reference:bugtraq,4482; reference:cve,2002-0073; reference:nessus,10934; reference:url,www.microsoft.com/technet/security/bulletin/MS02-018.mspx; classtype:attempted-dos; sid:2101777; rev:11; metadata:created_at 2010_09_23, updated_at 2017_03_21;)
` 

Name : **STAT * dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,4482|cve,2002-0073|nessus,10934|url,www.microsoft.com/technet/security/bulletin/MS02-018.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2017-03-21

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101778
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP STAT ? dos attempt"; flow:to_server,established; content:"STAT"; nocase; pcre:"/^STAT\s+[^\n]*\x3f/smi"; reference:bugtraq,4482; reference:cve,2002-0073; reference:nessus,10934; reference:url,www.microsoft.com/technet/security/bulletin/MS02-018.mspx; classtype:attempted-dos; sid:2101778; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STAT ? dos attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : bugtraq,4482|cve,2002-0073|nessus,10934|url,www.microsoft.com/technet/security/bulletin/MS02-018.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101779
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP CWD .... attempt"; flow:to_server,established; content:"CWD "; content:" ...."; reference:bugtraq,4884; classtype:denial-of-service; sid:2101779; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD .... attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,4884

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101748
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP command overflow attempt"; flow:to_server,established,no_stream; dsize:>100; reference:bugtraq,4638; reference:cve,2002-0606; classtype:protocol-command-decode; sid:2101748; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **command overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,4638|cve,2002-0606

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101728
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP CWD ~<CR><NEWLINE> attempt"; flow:to_server,established; content:"CWD "; content:" ~|0D 0A|"; reference:bugtraq,2601; reference:cve,2001-0421; classtype:denial-of-service; sid:2101728; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD ~<CR><NEWLINE> attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,2601|cve,2001-0421

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102391
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP APPE overflow attempt"; flow:to_server,established; content:"APPE"; nocase; isdataat:100,relative; pcre:"/^APPE\s[^\n]{100}/smi"; reference:bugtraq,8315; reference:bugtraq,8542; reference:cve,2000-0133; reference:cve,2003-0466; classtype:attempted-admin; sid:2102391; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **APPE overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8315|bugtraq,8542|cve,2000-0133|cve,2003-0466

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101672
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP CWD ~ attempt"; flow:to_server,established; content:"CWD"; nocase; pcre:"/^CWD\s+~/smi"; reference:bugtraq,2601; reference:bugtraq,9215; reference:cve,2001-0421; classtype:denial-of-service; sid:2101672; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD ~ attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,2601|bugtraq,9215|cve,2001-0421

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101625
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP large SYST command"; flow:to_server,established; dsize:10; content:"SYST"; nocase; classtype:protocol-command-decode; sid:2101625; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **large SYST command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101623
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP invalid MODE"; flow:to_server,established; content:"MODE"; nocase; pcre:"/^MODE\s+[^ABSC]{1}/msi"; classtype:protocol-command-decode; sid:2101623; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **invalid MODE** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101622
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP RNFR ././ attempt"; flow:to_server,established; content:"RNFR "; nocase; content:" ././"; nocase; classtype:misc-attack; sid:2101622; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RNFR ././ attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101529
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE overflow attempt"; flow:to_server,established; content:"SITE"; nocase; isdataat:100,relative; pcre:"/^SITE\s[^\n]{100}/smi"; reference:cve,1999-0838; reference:cve,2001-0755; reference:cve,2001-0770; classtype:attempted-admin; sid:2101529; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : cve,1999-0838|cve,2001-0755|cve,2001-0770

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101562
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE CHOWN overflow attempt"; flow:to_server,established; content:"SITE"; nocase; content:"CHOWN"; distance:0; nocase; isdataat:100,relative; pcre:"/^SITE\s+CHOWN\s[^\n]{100}/smi"; reference:bugtraq,2120; reference:cve,2001-0065; classtype:attempted-admin; sid:2101562; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE CHOWN overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,2120|cve,2001-0065

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101928
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP shadow retrieval attempt"; flow:to_server,established; content:"RETR"; nocase; content:"shadow"; classtype:suspicious-filename-detect; sid:2101928; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **shadow retrieval attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2010731
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP FTP CWD command attempt without login"; flow:established,to_server; flowbits:isnotset,ET.ftp.user.login; content:!"USER"; depth:4; content:"CWD"; nocase; reference:url,www.nsftools.com/tips/RawFTP.htm; reference:url,doc.emergingthreats.net/2010731; classtype:attempted-recon; sid:2010731; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP CWD command attempt without login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.nsftools.com/tips/RawFTP.htm|url,doc.emergingthreats.net/2010731

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2002850
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET FTP USER login flowbit"; flow:established,to_server; content:"USER "; nocase; depth:5; flowbits:set,ET.ftp.user.login; flowbits:noalert; reference:url,doc.emergingthreats.net/bin/view/Main/2002850; classtype:not-suspicious; sid:2002850; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **USER login flowbit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002850

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100543
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP 'STOR 1MB' possible warez site"; flow:to_server,established; content:"STOR"; nocase; content:"1MB"; distance:1; nocase; classtype:misc-activity; sid:2100543; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP 'STOR 1MB' possible warez site** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100544
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP 'RETR 1MB' possible warez site"; flow:to_server,established; content:"RETR"; nocase; content:"1MB"; distance:1; nocase; classtype:misc-activity; sid:2100544; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP 'RETR 1MB' possible warez site** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100545
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP 'CWD / ' possible warez site"; flow:to_server,established; content:"CWD"; nocase; content:"/ "; distance:1; classtype:misc-activity; sid:2100545; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP 'CWD / ' possible warez site** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100546
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP 'CWD  ' possible warez site"; flow:to_server,established; content:"CWD  "; depth:5; nocase; classtype:misc-activity; sid:2100546; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP 'CWD  ' possible warez site** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100548
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP 'MKD .' possible warez site"; flow:to_server,established; content:"MKD ."; depth:5; nocase; classtype:misc-activity; sid:2100548; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP 'MKD .' possible warez site** 

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

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100553
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP anonymous login attempt"; flow:to_server,established; content:"USER "; depth:5; nocase; content:"anon"; distance:0; classtype:misc-activity; sid:2100553; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP anonymous login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100547
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP MKD space space possible warez site"; flow:to_server,established; content:"MKD  "; depth:5; nocase; classtype:misc-activity; sid:2100547; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MKD space space possible warez site** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101624
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP large PWD command"; flow:to_server,established; content:"PWD"; isdataat:7,relative; content:!"|0A|"; within:7; nocase; classtype:protocol-command-decode; sid:2101624; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **large PWD command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100308
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP NextFTP client overflow"; flow:to_client,established; content:"|B4| |B4|!|8B CC 83 E9 04 8B 19|3|C9|f|B9 10|"; fast_pattern:only; reference:bugtraq,572; reference:cve,1999-0671; classtype:attempted-user; sid:2100308; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NextFTP client overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,572|cve,1999-0671

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100349
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP MKD overflow"; flow:to_server,established; content:"MKD "; isdataat:100,relative; reference:bugtraq,113; reference:bugtraq,2242; reference:cve,1999-0368; classtype:attempted-admin; sid:2100349; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MKD overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,113|bugtraq,2242|cve,1999-0368

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100339
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP OpenBSD x86 ftpd"; flow:to_server,established; content:" |90|1|C0 99|RR|B0 17 CD 80|h|CC|sh"; fast_pattern:only; reference:arachnids,446; reference:bugtraq,2124; reference:cve,2001-0053; classtype:attempted-user; sid:2100339; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **OpenBSD x86 ftpd** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,446|bugtraq,2124|cve,2001-0053

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100338
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE EXEC format string"; flow:to_server,established; content:"SITE EXEC %020d|7C|%.f%.f|7C 0A|"; depth:32; nocase; reference:arachnids,453; reference:bugtraq,1387; reference:cve,2000-0573; classtype:attempted-user; sid:2100338; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE EXEC format string** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,453|bugtraq,1387|cve,2000-0573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100340
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP PWD overflow"; flow:to_server,established; content:"PWD|0A|/i"; fast_pattern:only; classtype:attempted-admin; sid:2100340; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PWD overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100341
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP XXXXX overflow"; flow:to_server,established; content:"XXXXX/"; fast_pattern:only; classtype:attempted-admin; sid:2100341; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **XXXXX overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100346
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0 site exec format string check"; flow:to_server,established; content:"f%.f%.f%.f%.f%."; depth:32; reference:arachnids,286; reference:bugtraq,1387; reference:cve,2000-0573; classtype:attempted-recon; sid:2100346; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0 site exec format string check** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,286|bugtraq,1387|cve,2000-0573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100343
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0 site exec format string overflow FreeBSD"; flow:to_server,established; content:"1|C0|PPP|B0|~|CD 80|1|DB|1|C0|"; depth:32; reference:arachnids,228; reference:bugtraq,1387; reference:cve,2000-0573; classtype:attempted-admin; sid:2100343; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0 site exec format string overflow FreeBSD** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,228|bugtraq,1387|cve,2000-0573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100344
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0 site exec format string overflow Linux"; flow:to_server,established; content:"1|C0|1|DB|1|C9 B0|F|CD 80|1|C0|1|DB|"; fast_pattern:only; reference:arachnids,287; reference:bugtraq,1387; reference:cve,2000-0573; classtype:attempted-admin; sid:2100344; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0 site exec format string overflow Linux** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,287|bugtraq,1387|cve,2000-0573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100342
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0 site exec format string overflow Solaris 2.8"; flow:to_server,established; content:"|90 1B C0 0F 82 10| |17 91 D0| |08|"; fast_pattern:only; reference:arachnids,451; reference:bugtraq,1387; reference:cve,2000-0573; classtype:attempted-user; sid:2100342; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0 site exec format string overflow Solaris 2.8** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,451|bugtraq,1387|cve,2000-0573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100345
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0 site exec format string overflow generic"; flow:to_server,established; content:"SITE "; nocase; content:" EXEC "; nocase; content:" %p"; nocase; fast_pattern; reference:arachnids,285; reference:bugtraq,1387; reference:cve,2000-0573; reference:nessus,10452; classtype:attempted-admin; sid:2100345; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0 site exec format string overflow generic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : arachnids,285|bugtraq,1387|cve,2000-0573|nessus,10452

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100348
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP wu-ftpd 2.6.0"; flow:to_server,established; content:"..11venglin@"; reference:arachnids,440; reference:bugtraq,1387; classtype:attempted-user; sid:2100348; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **wu-ftpd 2.6.0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : arachnids,440|bugtraq,1387

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100360
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP serv-u directory transversal"; flow:to_server,established; content:".%20."; nocase; fast_pattern:only; reference:bugtraq,2052; reference:cve,2001-0054; classtype:bad-unknown; sid:2100360; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **serv-u directory transversal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,2052|cve,2001-0054

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100361
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP SITE EXEC attempt"; flow:to_server,established; content:"SITE"; nocase; content:"EXEC"; distance:0; nocase; pcre:"/^SITE\s+EXEC/smi"; reference:arachnids,317; reference:bugtraq,2241; reference:cve,1999-0080; reference:cve,1999-0955; classtype:bad-unknown; sid:2100361; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE EXEC attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,317|bugtraq,2241|cve,1999-0080|cve,1999-0955

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102344
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP XCWD overflow attempt"; flow:to_server,established; content:"XCWD"; nocase; isdataat:100,relative; pcre:"/^XCWD\s[^\n]{100}/smi"; reference:bugtraq,11542; reference:bugtraq,8704; classtype:attempted-admin; sid:2102344; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **XCWD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,11542|bugtraq,8704

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102343
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP STOR overflow attempt"; flow:to_server,established; content:"STOR"; nocase; isdataat:100,relative; pcre:"/^STOR\s[^\n]{100}/smi"; reference:bugtraq,8668; reference:cve,2000-0133; classtype:attempted-admin; sid:2102343; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STOR overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8668|cve,2000-0133

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102340
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP SITE CHMOD overflow attempt"; flow:to_server,established; content:"SITE"; nocase; content:"CHMOD"; distance:0; nocase; isdataat:100,relative; pcre:"/^SITE\s+CHMOD\s[^\n]{100}/smi"; reference:bugtraq,10181; reference:bugtraq,9483; reference:bugtraq,9675; reference:cve,1999-0838; reference:nessus,12037; classtype:attempted-admin; sid:2102340; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SITE CHMOD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10181|bugtraq,9483|bugtraq,9675|cve,1999-0838|nessus,12037

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102338
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP LIST buffer overflow attempt"; flow:to_server,established; content:"LIST"; nocase; isdataat:100,relative; pcre:"/^LIST\s[^\n]{100,}/smi"; reference:bugtraq,10181; reference:bugtraq,6869; reference:bugtraq,7251; reference:bugtraq,7861; reference:bugtraq,8486; reference:bugtraq,9675; reference:cve,1999-0349; reference:cve,1999-1510; reference:cve,2000-0129; reference:url,www.microsoft.com/technet/security/bulletin/MS99-003.mspx; classtype:misc-attack; sid:2102338; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **LIST buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,10181|bugtraq,6869|bugtraq,7251|bugtraq,7861|bugtraq,8486|bugtraq,9675|cve,1999-0349|cve,1999-1510|cve,2000-0129|url,www.microsoft.com/technet/security/bulletin/MS99-003.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102333
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RENAME format string attempt"; flow:to_server,established; content:"RENAME"; nocase; pcre:"/^RENAME\s[^\n]*?%[^\n]*?%/smi"; reference:bugtraq,9262; classtype:misc-attack; sid:2102333; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RENAME format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9262

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102332
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP MKDIR format string attempt"; flow:to_server,established; content:"MKDIR"; nocase; pcre:"/^MKDIR\s[^\n]*?%[^\n]*?%/smi"; reference:bugtraq,9262; classtype:misc-attack; sid:2102332; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MKDIR format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,9262

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102179
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP PASS format string attempt"; flow:to_server,established; content:"PASS"; nocase; pcre:"/^PASS\s[^\n]*?%[^\n]*?%/smi"; reference:bugtraq,7474; reference:bugtraq,9262; reference:bugtraq,9800; reference:cve,2000-0699; classtype:misc-attack; sid:2102179; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PASS format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,7474|bugtraq,9262|bugtraq,9800|cve,2000-0699

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102178
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP USER format string attempt"; flow:to_server,established; content:"USER"; nocase; pcre:"/^USER\s[^\n]*?%[^\n]*?%/smi"; reference:bugtraq,7474; reference:bugtraq,7776; reference:bugtraq,9262; reference:bugtraq,9402; reference:bugtraq,9600; reference:bugtraq,9800; reference:cve,2004-0277; reference:nessus,10041; reference:nessus,11687; classtype:misc-attack; sid:2102178; rev:17; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **USER format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,7474|bugtraq,7776|bugtraq,9262|bugtraq,9402|bugtraq,9600|bugtraq,9800|cve,2004-0277|nessus,10041|nessus,11687

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 17

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102125
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP CWD Root directory transversal attempt"; flow:to_server,established; content:"CWD"; nocase; content:"C|3A 5C|"; distance:1; fast_pattern; reference:bugtraq,7674; reference:cve,2003-0392; reference:nessus,11677; classtype:protocol-command-decode; sid:2102125; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD Root directory transversal attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : bugtraq,7674|cve,2003-0392|nessus,11677

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102546
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP MDTM overflow attempt"; flow:to_server,established; content:"MDTM"; nocase; isdataat:100,relative; pcre:"/^MDTM\s[^\n]{100}/smi"; reference:bugtraq,9751; reference:cve,2001-1021; reference:cve,2004-0330; reference:nessus,12080; classtype:attempted-admin; sid:2102546; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MDTM overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9751|cve,2001-1021|cve,2004-0330|nessus,12080

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102574
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RETR format string attempt"; flow:to_server,established; content:"RETR"; nocase; pcre:"/^RETR\s[^\n]*?%[^\n]*?%/smi"; reference:bugtraq,9800; classtype:attempted-admin; sid:2102574; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RETR format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9800

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011487
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Suspicious Percentage Symbol Usage in FTP Username"; flow:established,to_server; content:"USER "; depth:5; nocase; content:!"|0d 0a|"; within:50; content:"%"; distance:0; metadata: former_category FTP; reference:url,www.checkpoint.com/defense/advisories/public/2010/sbp-16-Aug.html; classtype:bad-unknown; sid:2011487; rev:2; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Suspicious Percentage Symbol Usage in FTP Username** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.checkpoint.com/defense/advisories/public/2010/sbp-16-Aug.html

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101229
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP CWD ..."; flow:to_server,established; content:"CWD"; nocase; content:"..."; distance:0; pcre:"/^CWD\s[^\n]*?\.\.\./smi"; reference:bugtraq,9237; classtype:bad-unknown; sid:2101229; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD ...** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,9237

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100336
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP CWD ~root attempt"; flow:to_server,established; content:"CWD"; nocase; content:"~root"; distance:1; nocase; pcre:"/^CWD\s+~root/smi"; reference:arachnids,318; reference:cve,1999-0082; classtype:bad-unknown; sid:2100336; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **CWD ~root attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,318|cve,1999-0082

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102374
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP NLST overflow attempt"; flow:to_server,established; content:"NLST"; nocase; isdataat:100,relative; pcre:"/^NLST\s[^\n]{100}/smi"; reference:bugtraq,10184; reference:bugtraq,7909; reference:bugtraq,9675; reference:cve,1999-1544; classtype:attempted-admin; sid:2102374; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **NLST overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10184|bugtraq,7909|bugtraq,9675|cve,1999-1544

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103441
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP PORT bounce attempt"; flow:to_server,established; content:"PORT"; nocase; ftpbounce; pcre:"/^PORT/smi"; classtype:misc-attack; sid:2103441; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PORT bounce attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103460
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP REST with numeric argument"; flow:to_server,established; content:"REST"; nocase; pcre:"/REST\s+[0-9]+\n/i"; reference:bugtraq,7825; classtype:attempted-recon; sid:2103460; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **REST with numeric argument** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,7825

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102392
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RETR overflow attempt"; flow:to_server,established; content:"RETR"; nocase; isdataat:100,relative; pcre:"/^RETR\s[^\n]{100}/smi"; reference:bugtraq,8315; reference:cve,2003-0466; reference:cve,2004-0287; reference:cve,2004-0298; classtype:attempted-admin; sid:2102392; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RETR overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8315|cve,2003-0466|cve,2004-0287|cve,2004-0298

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2103077
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RNFR overflow attempt"; flow:to_server,established; content:"RNFR"; nocase; isdataat:100,relative; pcre:"/^RNFR\s[^\n]{100}/smi"; classtype:attempted-admin; sid:2103077; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RNFR overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102389
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP RNTO overflow attempt"; flow:to_server,established; content:"RNTO"; nocase; isdataat:100,relative; pcre:"/^RNTO\s[^\n]{100}/smi"; reference:bugtraq,8315; reference:cve,2000-0133; reference:cve,2001-1021; reference:cve,2003-0466; classtype:attempted-admin; sid:2102389; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **RNTO overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8315|cve,2000-0133|cve,2001-1021|cve,2003-0466

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101379
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP STAT overflow attempt"; flow:to_server,established; content:"STAT"; nocase; isdataat:100,relative; pcre:"/^STAT\s[^\n]{100}/smi"; reference:bugtraq,3507; reference:bugtraq,8542; reference:cve,2001-0325; reference:cve,2001-1021; reference:url,labs.defcom.com/adv/2001/def-2001-31.txt; classtype:attempted-admin; sid:2101379; rev:13; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STAT overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,3507|bugtraq,8542|cve,2001-0325|cve,2001-1021|url,labs.defcom.com/adv/2001/def-2001-31.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 13

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102390
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP STOU overflow attempt"; flow:to_server,established; content:"STOU"; nocase; isdataat:100,relative; pcre:"/^STOU\s[^\n]{100}/smi"; reference:bugtraq,8315; reference:cve,2003-0466; classtype:attempted-admin; sid:2102390; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **STOU overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,8315|cve,2003-0466

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102373
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP XMKD overflow attempt"; flow:to_server,established; content:"XMKD"; nocase; isdataat:100,relative; pcre:"/^XMKD\s[^\n]{100}/smi"; reference:bugtraq,7909; reference:cve,2000-0133; reference:cve,2001-1021; classtype:attempted-admin; sid:2102373; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **XMKD overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,7909|cve,2000-0133|cve,2001-1021

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102417
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP format string attempt"; flow:to_server,established; content:"%"; fast_pattern:only; pcre:"/\s+.*?%.*?%/smi"; classtype:string-detect; sid:2102417; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101530
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP format string attempt"; flow:to_server,established; content:"%p"; nocase; reference:nessus,10452; reference:bugtraq,1387; reference:bugtraq,2240; reference:bugtraq,726; reference:cve,2000-0573; reference:cve,1999-0997; classtype:attempted-admin; sid:2101530; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **format string attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : nessus,10452|bugtraq,1387|bugtraq,2240|bugtraq,726|cve,2000-0573|cve,1999-0997

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100356
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP passwd retrieval attempt"; flow:to_server,established; content:"RETR"; nocase; content:"passwd"; reference:arachnids,213; classtype:suspicious-filename-detect; sid:2100356; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **passwd retrieval attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : arachnids,213

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100491
`#alert ftp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL FTP FTP Bad login"; flow:from_server,established; content:"530 "; depth:4; pcre:"/^530\s+(Login|User)/smi"; classtype:bad-unknown; sid:2100491; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP Bad login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100489
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP no password"; flow:from_client,established; content:"PASS"; nocase; pcre:"/^PASS\s*\n/smi"; reference:arachnids,322; classtype:unknown; sid:2100489; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP no password** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unknown

URL reference : arachnids,322

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100554
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP MKD / possible warez site"; flow:to_server,established; content:"MKD"; nocase; content:"/ "; distance:1; classtype:misc-activity; sid:2100554; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MKD / possible warez site** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101449
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP anonymous ftp login attempt"; flow:to_server,established; content:"USER"; nocase; content:" ftp|0D 0A|"; nocase; classtype:misc-activity; sid:2101449; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP anonymous ftp login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101445
`#alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP FTP file_id.diz access possible warez site"; flow:to_server,established; content:"RETR"; nocase; content:"file_id.diz"; distance:1; nocase; classtype:suspicious-filename-detect; sid:2101445; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **FTP file_id.diz access possible warez site** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102272
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"GPL FTP LIST integer overflow attempt"; flow:to_server,established; content:"LIST"; nocase; pcre:"/^LIST\s+\x22-W\s+\d/smi"; reference:bugtraq,8875; reference:cve,2003-0853; reference:cve,2003-0854; classtype:misc-attack; sid:2102272; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **LIST integer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,8875|cve,2003-0853|cve,2003-0854

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016687
`alert ftp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET FTP Outbound Java Anonymous FTP Login"; flow:to_server,established; content:"USER anonymous|0d 0a|PASS Java1."; fast_pattern:7,20; pcre:"/^\d\.\d(_\d+)?\@\r\n/R"; flowbits:set,ET.Java.FTP.Logon; classtype:misc-activity; sid:2016687; rev:3; metadata:created_at 2013_03_28, updated_at 2013_03_28;)
` 

Name : **Outbound Java Anonymous FTP Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-28

Last modified date : 2013-03-28

Rev version : 3

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101927
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP authorized_keys file transferred"; flow:to_server,established; content:"authorized_keys"; classtype:suspicious-filename-detect; sid:2101927; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **authorized_keys file transferred** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011994
`#alert tcp any any -> $HOME_NET 21 (msg:"ET FTP ProFTPD Backdoor Inbound Backdoor Open Request (ACIDBITCHEZ)"; flow:established,to_server; content:"HELP "; depth:5; content:"ACIDBITCHEZ"; distance:0; nocase; reference:url,slashdot.org/story/10/12/02/131214/ProFTPDorg-Compromised-Backdoor-Distributed; reference:url,xorl.wordpress.com/2010/12/02/news-proftpd-owned-and-backdoored/; reference:url, sourceforge.net/mailarchive/message.php?msg_name=alpine.DEB.2.00.1012011542220.12930%40familiar.castaglia.org; classtype:trojan-activity; sid:2011994; rev:5; metadata:created_at 2010_12_02, updated_at 2010_12_02;)
` 

Name : **ProFTPD Backdoor Inbound Backdoor Open Request (ACIDBITCHEZ)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,slashdot.org/story/10/12/02/131214/ProFTPDorg-Compromised-Backdoor-Distributed|url,xorl.wordpress.com/2010/12/02/news-proftpd-owned-and-backdoored/|url, sourceforge.net/mailarchive/message.php?msg_name=alpine.DEB.2.00.1012011542220.12930%40familiar.castaglia.org

CVE reference : Not defined

Creation date : 2010-12-02

Last modified date : 2010-12-02

Rev version : 5

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2011488
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Suspicious Quotation Mark Usage in FTP Username"; flow:established,to_server; content:"USER "; depth:5; content:"|22|"; distance:0; pcre:"/^USER [^\r\n]*?\x22/";  metadata: former_category FTP; reference:url,www.checkpoint.com/defense/advisories/public/2010/sbp-16-Aug.html; classtype:bad-unknown; sid:2011488; rev:2; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Suspicious Quotation Mark Usage in FTP Username** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.checkpoint.com/defense/advisories/public/2010/sbp-16-Aug.html

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 2

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2101734
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP USER overflow attempt"; flow:to_server,established,no_stream; content:"USER|20|"; nocase; isdataat:100,relative; pcre:"/^USER\x20[^\x00\x20\x0a\x0d]{100}/smi"; reference:bugtraq,10078; reference:bugtraq,1227; reference:bugtraq,1504; reference:bugtraq,1690; reference:bugtraq,4638; reference:bugtraq,7307; reference:bugtraq,8376; reference:cve,1999-1510; reference:cve,1999-1514; reference:cve,1999-1519; reference:cve,1999-1539; reference:cve,2000-0479; reference:cve,2000-0656; reference:cve,2000-0761; reference:cve,2000-0943; reference:cve,2000-1035; reference:cve,2000-1194; reference:cve,2001-0256; reference:cve,2001-0794; reference:cve,2001-0826; reference:cve,2002-0126; reference:cve,2002-1522; reference:cve,2003-0271; reference:cve,2004-0286; classtype:attempted-admin; sid:2101734; rev:36; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **USER overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,10078|bugtraq,1227|bugtraq,1504|bugtraq,1690|bugtraq,4638|bugtraq,7307|bugtraq,8376|cve,1999-1510|cve,1999-1514|cve,1999-1519|cve,1999-1539|cve,2000-0479|cve,2000-0656|cve,2000-0761|cve,2000-0943|cve,2000-1035|cve,2000-1194|cve,2001-0256|cve,2001-0794|cve,2001-0826|cve,2002-0126|cve,2002-1522|cve,2003-0271|cve,2004-0286

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 36

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100354
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP iss scan"; flow:to_server,established; content:"pass -iss@iss"; fast_pattern; reference:arachnids,331; classtype:suspicious-login; sid:2100354; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **iss scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,331

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100355
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP pass wh00t"; flow:to_server,established; content:"pass wh00t"; nocase; fast_pattern; reference:arachnids,324; classtype:suspicious-login; sid:2100355; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **pass wh00t** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,324

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100357
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP piss scan"; flow:to_server,established; content:"pass -cklaus"; fast_pattern; classtype:suspicious-login; sid:2100357; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **piss scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100358
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP saint scan"; flow:to_server,established; content:"pass -saint"; fast_pattern; reference:arachnids,330; classtype:suspicious-login; sid:2100358; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **saint scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,330

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100359
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP satan scan"; flow:to_server,established; content:"pass -satan"; fast_pattern; reference:arachnids,329; classtype:suspicious-login; sid:2100359; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **satan scan** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : arachnids,329

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2100362
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP tar parameters"; flow:to_server,established; content:" --use-compress-program "; nocase; fast_pattern; reference:arachnids,134; reference:bugtraq,2240; reference:cve,1999-0202; reference:cve,1999-0997; classtype:bad-unknown; sid:2100362; rev:15; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **tar parameters** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,134|bugtraq,2240|cve,1999-0202|cve,1999-0997

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 15

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2102416
`alert ftp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL FTP invalid MDTM command attempt"; flow:to_server,established; content:"MDTM"; fast_pattern; nocase; pcre:"/^MDTM \d+[-+]\D/smi"; reference:bugtraq,9751; reference:cve,2001-1021; reference:cve,2004-0330; classtype:attempted-admin; sid:2102416; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **invalid MDTM command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : bugtraq,9751|cve,2001-1021|cve,2004-0330

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : FTP

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

# 2016688
`alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"ET FTP Outbound Java Downloading jar over FTP"; flow:to_server,established; flowbits:isset,ET.Java.FTP.Logon; content:".jar"; nocase; fast_pattern; content:"RETR "; pcre:"/^[^\r\n]+\.jar/Ri"; classtype:misc-activity; sid:2016688; rev:3; metadata:created_at 2013_03_28, updated_at 2019_10_07;)
` 

Name : **Outbound Java Downloading jar over FTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-03-28

Last modified date : 2019-10-07

Rev version : 3

Category : FTP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

