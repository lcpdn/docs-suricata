# Emerging Threats 

#

# This distribution may contain rules under two different licenses. 

#

#  Rules with sids 1 through 3464, and 100000000 through 100000908 are under the GPLv2.

#  A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html

#

#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License 

#  as follows:

#

#*************************************************************

#  Copyright (c) 2003-2019, Emerging Threats

#  All rights reserved.

#  

#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 

#  following conditions are met:

#  

#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 

#    disclaimer.

#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 

#    following disclaimer in the documentation and/or other materials provided with the distribution.

#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 

#    from this software without specific prior written permission.

#  

#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 

#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 

#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 

#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 

#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 

#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 

#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

#

#*************************************************************

#

#

#

#



# This Ruleset is EmergingThreats Open optimized for suricata-4.0-enhanced.



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"ET SQL MSSQL sp_replwritetovarbin - potential memory overwrite case 1"; flow:to_server,established; content:"s|00|p|00|_|00|r|00|e|00|p|00|l|00|w|00|r|00|i|00|t|00|e|00|t|00|o|00|v|00|a|00|r|00|b|00|i|00|n"; nocase; reference:url,archives.neohapsis.com/archives/fulldisclosure/2008-12/0239.html; reference:url,doc.emergingthreats.net/bin/view/Main/2008909; classtype:attempted-user; sid:2008909; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008909
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"ET SQL MSSQL sp_replwritetovarbin - potential memory overwrite case 1"; flow:to_server,established; content:"s|00|p|00|_|00|r|00|e|00|p|00|l|00|w|00|r|00|i|00|t|00|e|00|t|00|o|00|v|00|a|00|r|00|b|00|i|00|n"; nocase; reference:url,archives.neohapsis.com/archives/fulldisclosure/2008-12/0239.html; reference:url,doc.emergingthreats.net/bin/view/Main/2008909; classtype:attempted-user; sid:2008909; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSSQL sp_replwritetovarbin - potential memory overwrite case 1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,archives.neohapsis.com/archives/fulldisclosure/2008-12/0239.html|url,doc.emergingthreats.net/bin/view/Main/2008909

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SQL

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 1434 (msg:"GPL SQL Slammer Worm propagation attempt"; content:"|04|"; depth:1; content:"|81 F1 03 01 04 9B 81 F1 01|"; content:"sock"; content:"send"; reference:bugtraq,5310; reference:bugtraq,5311; reference:cve,2002-0649; reference:nessus,11214; reference:url,vil.nai.com/vil/content/v_99992.htm; classtype:misc-attack; sid:2102003; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102003
`alert udp $EXTERNAL_NET any -> $HOME_NET 1434 (msg:"GPL SQL Slammer Worm propagation attempt"; content:"|04|"; depth:1; content:"|81 F1 03 01 04 9B 81 F1 01|"; content:"sock"; content:"send"; reference:bugtraq,5310; reference:bugtraq,5311; reference:cve,2002-0649; reference:nessus,11214; reference:url,vil.nai.com/vil/content/v_99992.htm; classtype:misc-attack; sid:2102003; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Slammer Worm propagation attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,5310|bugtraq,5311|cve,2002-0649|nessus,11214|url,vil.nai.com/vil/content/v_99992.htm

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"GPL SQL MYSQL root login attempt"; flow:to_server,established; content:"|0A 00 00 01 85 04 00 00 80|root|00|"; classtype:protocol-command-decode; sid:2101775; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101775
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"GPL SQL MYSQL root login attempt"; flow:to_server,established; content:"|0A 00 00 01 85 04 00 00 80|root|00|"; classtype:protocol-command-decode; sid:2101775; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MYSQL root login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"GPL SQL MYSQL show databases attempt"; flow:to_server,established; content:"|0F 00 00 00 03|show databases"; classtype:protocol-command-decode; sid:2101776; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101776
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 3306 (msg:"GPL SQL MYSQL show databases attempt"; flow:to_server,established; content:"|0F 00 00 00 03|show databases"; classtype:protocol-command-decode; sid:2101776; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MYSQL show databases attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL execute_system attempt"; flow:to_server,established; content:"EXECUTE_SYSTEM"; nocase; classtype:protocol-command-decode; sid:2101698; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101698
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL execute_system attempt"; flow:to_server,established; content:"EXECUTE_SYSTEM"; nocase; classtype:protocol-command-decode; sid:2101698; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **execute_system attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL connect_data remote version detection attempt"; flow:to_server,established; content:"connect_data|28|command=version|29|"; nocase; classtype:protocol-command-decode; sid:2101674; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101674
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL connect_data remote version detection attempt"; flow:to_server,established; content:"connect_data|28|command=version|29|"; nocase; classtype:protocol-command-decode; sid:2101674; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **connect_data remote version detection attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL EXECUTE_SYSTEM attempt"; flow:to_server,established; content:"EXECUTE_SYSTEM"; nocase; classtype:system-call-detect; sid:2101673; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101673
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL EXECUTE_SYSTEM attempt"; flow:to_server,established; content:"EXECUTE_SYSTEM"; nocase; classtype:system-call-detect; sid:2101673; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **EXECUTE_SYSTEM attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : system-call-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa brute force failed login attempt"; flow:from_server,established; content:"Login failed for user 'sa'"; threshold:type threshold, track by_src, count 5, seconds 2; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2103152; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2103152
`alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa brute force failed login attempt"; flow:from_server,established; content:"Login failed for user 'sa'"; threshold:type threshold, track by_src, count 5, seconds 2; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2103152; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sa brute force failed login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : bugtraq,4797|cve,2000-1209|nessus,10673

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $SQL_SERVERS any (msg:"GPL SQL probe response overflow attempt"; content:"|05|"; depth:1; byte_test:2,>,512,1; content:"|3B|"; distance:0; isdataat:512,relative; content:!"|3B|"; within:512; reference:bugtraq,9407; reference:cve,2003-0903; reference:url,www.microsoft.com/technet/security/bulletin/MS04-003.mspx; classtype:attempted-user; sid:2102329; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102329
`#alert udp $EXTERNAL_NET any -> $SQL_SERVERS any (msg:"GPL SQL probe response overflow attempt"; content:"|05|"; depth:1; byte_test:2,>,512,1; content:"|3B|"; distance:0; isdataat:512,relative; content:!"|3B|"; within:512; reference:bugtraq,9407; reference:cve,2003-0903; reference:url,www.microsoft.com/technet/security/bulletin/MS04-003.mspx; classtype:attempted-user; sid:2102329; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **probe response overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,9407|cve,2003-0903|url,www.microsoft.com/technet/security/bulletin/MS04-003.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 1434 (msg:"GPL SQL ping attempt"; content:"|02|"; depth:1; reference:nessus,10674; classtype:misc-activity; sid:2102049; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102049
`#alert udp $EXTERNAL_NET any -> $HOME_NET 1434 (msg:"GPL SQL ping attempt"; content:"|02|"; depth:1; reference:nessus,10674; classtype:misc-activity; sid:2102049; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ping attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : nessus,10674

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_support"; nocase; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*package_prefix[\r\n\s]*=>[\r\n\s]*\2|package_prefix\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*procedure_prefix[\r\n\s]*=>[\r\n\s]*\2|procedure_prefix\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck93.html; classtype:attempted-user; sid:2102576; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102576
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_support"; nocase; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*package_prefix[\r\n\s]*=>[\r\n\s]*\2|package_prefix\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*procedure_prefix[\r\n\s]*=>[\r\n\s]*\2|procedure_prefix\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck93.html; classtype:attempted-user; sid:2102576; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **dbms_repcat.generate_replication_support buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck93.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $SQL_SERVERS $ORACLE_PORTS -> $EXTERNAL_NET any (msg:"GPL SQL Oracle misparsed login response"; flow:to_server,established; content:"description=|28|"; nocase; content:!"connect_data=|28|sid="; nocase; content:!"address=|28|protocol=tcp"; nocase; classtype:suspicious-login; sid:2101675; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101675
`#alert tcp $SQL_SERVERS $ORACLE_PORTS -> $EXTERNAL_NET any (msg:"GPL SQL Oracle misparsed login response"; flow:to_server,established; content:"description=|28|"; nocase; content:!"connect_data=|28|sid="; nocase; content:!"address=|28|protocol=tcp"; nocase; classtype:suspicious-login; sid:2101675; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Oracle misparsed login response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL sp_password password change"; flow:to_server,established; content:"s|00|p|00|_|00|p|00|a|00|s|00|s|00|w|00|o|00|r|00|d|00|"; nocase; classtype:attempted-user; sid:2100677; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100677
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL sp_password password change"; flow:to_server,established; content:"s|00|p|00|_|00|p|00|a|00|s|00|s|00|w|00|o|00|r|00|d|00|"; nocase; classtype:attempted-user; sid:2100677; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_password password change** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL sp_delete_alert log file deletion"; flow:to_server,established; content:"s|00|p|00|_|00|d|00|e|00|l|00|e|00|t|00|e|00|_|00|a|00|l|00|e|00|"; nocase; classtype:attempted-user; sid:2100678; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100678
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL sp_delete_alert log file deletion"; flow:to_server,established; content:"s|00|p|00|_|00|d|00|e|00|l|00|e|00|t|00|e|00|_|00|a|00|l|00|e|00|"; nocase; classtype:attempted-user; sid:2100678; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_delete_alert log file deletion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $SQL_SERVERS 139 -> $EXTERNAL_NET any (msg:"GPL SQL sa login failed"; flow:from_server,established; content:"Login failed for user 'sa'"; offset:83; reference:bugtraq,4797; reference:cve,2000-1209; classtype:attempted-user; sid:2100680; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100680
`alert tcp $SQL_SERVERS 139 -> $EXTERNAL_NET any (msg:"GPL SQL sa login failed"; flow:from_server,established; content:"Login failed for user 'sa'"; offset:83; reference:bugtraq,4797; reference:cve,2000-1209; classtype:attempted-user; sid:2100680; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sa login failed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,4797|cve,2000-1209

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_password - password change"; flow:to_server,established; content:"s|00|p|00|_|00|p|00|a|00|s|00|s|00|w|00|o|00|r|00|d|00|"; nocase; classtype:attempted-user; sid:2100683; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100683
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_password - password change"; flow:to_server,established; content:"s|00|p|00|_|00|p|00|a|00|s|00|s|00|w|00|o|00|r|00|d|00|"; nocase; classtype:attempted-user; sid:2100683; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_password - password change** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_delete_alert log file deletion"; flow:to_server,established; content:"s|00|p|00|_|00|d|00|e|00|l|00|e|00|t|00|e|00|_|00|a|00|l|00|e|00|r|00|t|00|"; nocase; classtype:attempted-user; sid:2100684; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100684
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_delete_alert log file deletion"; flow:to_server,established; content:"s|00|p|00|_|00|d|00|e|00|l|00|e|00|t|00|e|00|_|00|a|00|l|00|e|00|r|00|t|00|"; nocase; classtype:attempted-user; sid:2100684; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_delete_alert log file deletion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_adduser - database user creation"; flow:to_server,established; content:"s|00|p|00|_|00|a|00|d|00|d|00|u|00|s|00|e|00|r|00|"; nocase; classtype:attempted-user; sid:2100685; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100685
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_adduser - database user creation"; flow:to_server,established; content:"s|00|p|00|_|00|a|00|d|00|d|00|u|00|s|00|e|00|r|00|"; nocase; classtype:attempted-user; sid:2100685; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_adduser - database user creation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa login failed"; flow:from_server,established; content:"Login failed for user 'sa'"; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2100688; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100688
`alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa login failed"; flow:from_server,established; content:"Login failed for user 'sa'"; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2100688; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sa login failed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : bugtraq,4797|cve,2000-1209|nessus,10673

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL xp_printstatements possible buffer overflow"; flow:to_server,established; content:"x|00|p|00|_|00|p|00|r|00|i|00|n|00|t|00|s|00|t|00|a|00|t|00|e|00|m|00|e|00|n|00|t|00|s|00|"; offset:32; nocase; reference:bugtraq,2041; reference:cve,2000-1086; reference:url,www.microsoft.com/technet/security/bulletin/MS00-092.mspx; classtype:attempted-user; sid:2100690; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100690
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL xp_printstatements possible buffer overflow"; flow:to_server,established; content:"x|00|p|00|_|00|p|00|r|00|i|00|n|00|t|00|s|00|t|00|a|00|t|00|e|00|m|00|e|00|n|00|t|00|s|00|"; offset:32; nocase; reference:bugtraq,2041; reference:cve,2000-1086; reference:url,www.microsoft.com/technet/security/bulletin/MS00-092.mspx; classtype:attempted-user; sid:2100690; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xp_printstatements possible buffer overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,2041|cve,2000-1086|url,www.microsoft.com/technet/security/bulletin/MS00-092.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL shellcode attempt"; flow:to_server,established; content:"9 |D0 00 92 01 C2 00|R|00|U|00|9 |EC 00|"; classtype:shellcode-detect; sid:2100692; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100692
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL shellcode attempt"; flow:to_server,established; content:"9 |D0 00 92 01 C2 00|R|00|U|00|9 |EC 00|"; classtype:shellcode-detect; sid:2100692; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **shellcode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL MSSQL shellcode attempt 2"; flow:to_server,established; content:"H|00|%|00|x|00|w|00 90 00 90 00 90 00 90 00 90 00|3|00 C0 00|P|00|h|00|.|00|"; classtype:shellcode-detect; sid:2100693; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100693
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL MSSQL shellcode attempt 2"; flow:to_server,established; content:"H|00|%|00|x|00|w|00 90 00 90 00 90 00 90 00 90 00|3|00 C0 00|P|00|h|00|.|00|"; classtype:shellcode-detect; sid:2100693; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSSQL shellcode attempt 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL shellcode attempt"; flow:to_server,established; content:"H|00|%|00|x|00|w|00 90 00 90 00 90 00 90 00 90 00|3|00 C0 00|P|00|h|00|.|00|"; classtype:attempted-user; sid:2100694; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100694
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL shellcode attempt"; flow:to_server,established; content:"H|00|%|00|x|00|w|00 90 00 90 00 90 00 90 00 90 00|3|00 C0 00|P|00|h|00|.|00|"; classtype:attempted-user; sid:2100694; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **shellcode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa brute force failed login unicode attempt"; flow:from_server,established; content:"L|00|o|00|g|00|i|00|n|00| |00|f|00|a|00|i|00|l|00|e|00|d|00| |00|f|00|o|00|r|00| |00|u|00|s|00|e|00|r|00| |00|'|00|s|00|a|00|'|00|"; threshold:type threshold, track by_src, count 5, seconds 2; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2103273; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2103273
`alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any (msg:"GPL SQL sa brute force failed login unicode attempt"; flow:from_server,established; content:"L|00|o|00|g|00|i|00|n|00| |00|f|00|a|00|i|00|l|00|e|00|d|00| |00|f|00|o|00|r|00| |00|u|00|s|00|e|00|r|00| |00|'|00|s|00|a|00|'|00|"; threshold:type threshold, track by_src, count 5, seconds 2; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:2103273; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sa brute force failed login unicode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : unsuccessful-user

URL reference : bugtraq,4797|cve,2000-1209|nessus,10673

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL TO_CHAR buffer overflow attempt"; flow:to_server,established; content:"TO_CHAR"; nocase; pcre:"/TO_CHAR\s*\(\s*SYSTIMESTAMP\s*,\s*(\x27[^\x27]{256}|\x22[^\x22]{256})/smi"; classtype:attempted-user; sid:2102699; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102699
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL TO_CHAR buffer overflow attempt"; flow:to_server,established; content:"TO_CHAR"; nocase; pcre:"/TO_CHAR\s*\(\s*SYSTIMESTAMP\s*,\s*(\x27[^\x27]{256}|\x22[^\x22]{256})/smi"; classtype:attempted-user; sid:2102699; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TO_CHAR buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL create file buffer overflow attempt"; flow:to_server,established; content:"create"; nocase; content:"file "; nocase; isdataat:512; pcre:"/CREATE\s.*?FILE\s+((AS|MEMBER|TO)\s+)?(\x27[^\x27]{512}|\x22[^\x22]{512})/smi"; classtype:attempted-user; sid:2102698; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102698
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL create file buffer overflow attempt"; flow:to_server,established; content:"create"; nocase; content:"file "; nocase; isdataat:512; pcre:"/CREATE\s.*?FILE\s+((AS|MEMBER|TO)\s+)?(\x27[^\x27]{512}|\x22[^\x22]{512})/smi"; classtype:attempted-user; sid:2102698; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **create file buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL ctxsys.driddlr.subindexpopulate buffer overflow attempt"; flow:to_server,established; content:"ctxsys.driddlr.subindexpopulate"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*logfile[\r\n\s]*=>[\r\n\s]*\2|logfile\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\d+\s*,\s*){3}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102680; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102680
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL ctxsys.driddlr.subindexpopulate buffer overflow attempt"; flow:to_server,established; content:"ctxsys.driddlr.subindexpopulate"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*logfile[\r\n\s]*=>[\r\n\s]*\2|logfile\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\d+\s*,\s*){3}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102680; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ctxsys.driddlr.subindexpopulate buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_grouped_column buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_grouped_column"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102768; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102768
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_grouped_column buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_grouped_column"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102768; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **dbms_repcat.drop_grouped_column buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.md2.sdo_code_size buffer overflow attempt"; flow:to_server,established; content:"mdsys.md2.sdo_code_size"; nocase; isdataat:512,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{512,}\x27|\x22[^\x22]{512,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,})|\(\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,}))/si"; classtype:attempted-user; sid:2102683; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102683
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.md2.sdo_code_size buffer overflow attempt"; flow:to_server,established; content:"mdsys.md2.sdo_code_size"; nocase; isdataat:512,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{512,}\x27|\x22[^\x22]{512,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,})|\(\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,}))/si"; classtype:attempted-user; sid:2102683; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mdsys.md2.sdo_code_size buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.md2.validate_geom buffer overflow attempt"; flow:to_server,established; content:"mdsys.md2.validate_geom"; nocase; isdataat:500,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{128,}\x27|\x22[^\x22]{128,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{128,}|\x22[^\x22]{128,})|\(\s*(\x27[^\x27]{128,}|\x22[^\x22]{128,}))/si"; classtype:attempted-user; sid:2102682; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102682
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.md2.validate_geom buffer overflow attempt"; flow:to_server,established; content:"mdsys.md2.validate_geom"; nocase; isdataat:500,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{128,}\x27|\x22[^\x22]{128,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{128,}|\x22[^\x22]{128,})|\(\s*(\x27[^\x27]{128,}|\x22[^\x22]{128,}))/si"; classtype:attempted-user; sid:2102682; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mdsys.md2.validate_geom buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.sdo_admin.sdo_code_size buffer overflow attempt"; flow:to_server,established; content:"mdsys.sdo_admin.sdo_code_size"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102681; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102681
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL mdsys.sdo_admin.sdo_code_size buffer overflow attempt"; flow:to_server,established; content:"mdsys.sdo_admin.sdo_code_size"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*layer[\r\n\s]*=>[\r\n\s]*\2|layer\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102681; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **mdsys.sdo_admin.sdo_code_size buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL numtoyminterval buffer overflow attempt"; flow:to_server,established; content:"numtoyminterval"; nocase; pcre:"/numtoyminterval\s*\(\s*\d+\s*,\s*(\x27[^\x27]{32}|\x22[^\x22]{32})/smi"; classtype:attempted-user; sid:2102700; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102700
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL numtoyminterval buffer overflow attempt"; flow:to_server,established; content:"numtoyminterval"; nocase; pcre:"/numtoyminterval\s*\(\s*\d+\s*,\s*(\x27[^\x27]{32}|\x22[^\x22]{32})/smi"; classtype:attempted-user; sid:2102700; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **numtoyminterval buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL service_name buffer overflow attempt"; flow:to_server,established; content:"connect_data"; nocase; content:"|28|service_name="; nocase; isdataat:1000,relative; content:!"|22|"; within:1000; reference:url,www.appsecinc.com/Policy/PolicyCheck52.html; classtype:attempted-user; sid:2102649; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102649
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL service_name buffer overflow attempt"; flow:to_server,established; content:"connect_data"; nocase; content:"|28|service_name="; nocase; isdataat:1000,relative; content:!"|22|"; within:1000; reference:url,www.appsecinc.com/Policy/PolicyCheck52.html; classtype:attempted-user; sid:2102649; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **service_name buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck52.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aq_import_internal.aq_table_defn_update buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aq_import_internal.aq_table_defn_update"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*qt_name[\r\n\s]*=>[\r\n\s]*\2|qt_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102695; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102695
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aq_import_internal.aq_table_defn_update buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aq_import_internal.aq_table_defn_update"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*qt_name[\r\n\s]*=>[\r\n\s]*\2|qt_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102695; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_aq_import_internal.aq_table_defn_update buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm.verify_queue_types_get_nrp buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm.verify_queue_types_get_nrp"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102694; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102694
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm.verify_queue_types_get_nrp buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm.verify_queue_types_get_nrp"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102694; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_aqadm.verify_queue_types_get_nrp buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm.verify_queue_types_no_queue buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm.verify_queue_types_no_queue"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102693; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102693
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm.verify_queue_types_no_queue buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm.verify_queue_types_no_queue"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102693; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_aqadm.verify_queue_types_no_queue buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm_sys.verify_queue_types buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm_sys.verify_queue_types"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102692; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102692
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_aqadm_sys.verify_queue_types buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_aqadm_sys.verify_queue_types"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*src_queue_name[\r\n\s]*=>[\r\n\s]*\2|src_queue_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102692; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_aqadm_sys.verify_queue_types buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_defer_internal_sys.parallel_push_recovery buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_defer_internal_sys.parallel_push_recovery"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*destination[\r\n\s]*=>[\r\n\s]*\2|destination\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102691; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102691
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_defer_internal_sys.parallel_push_recovery buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_defer_internal_sys.parallel_push_recovery"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*destination[\r\n\s]*=>[\r\n\s]*\2|destination\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102691; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_defer_internal_sys.parallel_push_recovery buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_defer_repcat.enable_propagation_to_dblink buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_defer_repcat.enable_propagation_to_dblink"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*dblink[\r\n\s]*=>[\r\n\s]*\2|dblink\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102690; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102690
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_defer_repcat.enable_propagation_to_dblink buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_defer_repcat.enable_propagation_to_dblink"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*dblink[\r\n\s]*=>[\r\n\s]*\2|dblink\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102690; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_defer_repcat.enable_propagation_to_dblink buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.disable_receiver_trace buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.disable_receiver_trace"; nocase; isdataat:1024; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102689; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102689
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.disable_receiver_trace buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.disable_receiver_trace"; nocase; isdataat:1024; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102689; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_internal_repcat.disable_receiver_trace buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.enable_receiver_trace buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.enable_receiver_trace"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102688; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102688
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.enable_receiver_trace buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.enable_receiver_trace"; nocase; isdataat:1024,relative; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102688; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_internal_repcat.enable_receiver_trace buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.validate buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.validate"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102687; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102687
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_internal_repcat.validate buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_internal_repcat.validate"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102687; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_internal_repcat.validate buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_rectifier_diff.differences buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_rectifier_diff.differences"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*missing_rows_oname1[\r\n\s]*=>[\r\n\s]*\2|missing_rows_oname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname1[\r\n\s]*=>[\r\n\s]*\2|sname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102686; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102686
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_rectifier_diff.differences buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_rectifier_diff.differences"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*missing_rows_oname1[\r\n\s]*=>[\r\n\s]*\2|missing_rows_oname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname1[\r\n\s]*=>[\r\n\s]*\2|sname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102686; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_rectifier_diff.differences buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_rectifier_diff.rectify buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_rectifier_diff.rectify"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*missing_rows_oname1[\r\n\s]*=>[\r\n\s]*\2|missing_rows_oname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname1[\r\n\s]*=>[\r\n\s]*\2|sname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102633; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102633
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_rectifier_diff.rectify buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_rectifier_diff.rectify"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*missing_rows_oname1[\r\n\s]*=>[\r\n\s]*\2|missing_rows_oname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname1[\r\n\s]*=>[\r\n\s]*\2|sname1\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102633; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_rectifier_diff.rectify buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat.alter_mview_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat.alter_mview_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102617; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102617
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat.alter_mview_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat.alter_mview_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102617; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat.alter_mview_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_auth.grant_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_auth.grant_surrogate_repcat"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102615; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102615
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_auth.grant_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_auth.grant_surrogate_repcat"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102615; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_auth.grant_surrogate_repcat buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_auth.revoke_surrogate_repcat"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102612; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102612
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_auth.revoke_surrogate_repcat"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102612; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102858; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102858
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102858; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102861; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102861
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102861; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102862; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102862
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102862; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_number buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_nvarchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102863; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102863
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_nvarchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102863; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_nvarchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_raw"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102864; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102864
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_raw"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102864; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_varchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102865; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102865
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_varchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102865; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_site_priority_site"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102866; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102866
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_site_priority_site"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102866; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102867; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102867
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102867; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102868; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102868
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102868; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102875; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102875
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102875; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_char"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102869; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102869
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_char"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102869; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102870; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102870
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102870; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102871; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102871
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102871; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102872; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102872
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102872; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_number buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_raw"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102874; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102874
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_raw"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102874; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_varchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102876; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102876
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_priority_varchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102876; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102878; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102878
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102878; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.alter_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.cancel_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.cancel_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102879; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102879
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.cancel_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.cancel_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102879; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.cancel_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102880; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102880
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102880; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.comment_on_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_priority_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_priority_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102881; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102881
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_priority_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_priority_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102881; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.comment_on_priority_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102882; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102882
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102882; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.comment_on_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102883; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102883
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102883; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.comment_on_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102884; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102884
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.comment_on_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.comment_on_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102884; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.comment_on_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.define_priority_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.define_priority_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102885; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102885
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.define_priority_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.define_priority_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102885; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.define_priority_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.define_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.define_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102886; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102886
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.define_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.define_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102886; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.define_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102887; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102887
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_delete_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102887; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102894; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102894
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102894; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_char"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102888; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102888
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_char"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102888; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102889; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102889
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102889; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102890; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102890
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_nchar"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102890; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102891; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102891
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_number buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_number"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102891; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_number buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102897; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102897
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_site_priority buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_site_priority"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102897; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_site_priority_site"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102896; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102896
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_site_priority_site"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102896; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102898; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102898
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_unique_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102898; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102899; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102899
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_update_resolution buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_update_resolution"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102899; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.purge_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.purge_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102900; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102900
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.purge_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.purge_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102900; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.purge_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.register_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.register_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102901; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102901
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.register_statistics buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.register_statistics"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102901; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.register_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.abort_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.abort_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102813; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102813
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.abort_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.abort_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102813; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.abort_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.add_object_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.add_object_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102814; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102814
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.add_object_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.add_object_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102814; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.add_object_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.begin_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.begin_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102815; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102815
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.begin_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.begin_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102815; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.begin_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.drop_object_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.drop_object_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102816; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102816
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.drop_object_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.drop_object_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102816; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.drop_object_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.ensure_not_published buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.ensure_not_published"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck96.html; classtype:attempted-user; sid:2102643; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102643
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.ensure_not_published buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.ensure_not_published"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck96.html; classtype:attempted-user; sid:2102643; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.ensure_not_published buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck96.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.set_local_flavor"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102824; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102824
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.set_local_flavor"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102824; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.set_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.validate_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.validate_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102825; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102825
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.validate_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.validate_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102825; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.validate_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.validate_for_local_flavor"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102826; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102826
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla.validate_for_local_flavor"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102826; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla.validate_for_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.add_column_group_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.add_column_group_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102817; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102817
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.add_column_group_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.add_column_group_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102817; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.add_column_group_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.add_columns_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.add_columns_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102818; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102818
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.add_columns_to_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.add_columns_to_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102818; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.add_columns_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.drop_column_group_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.drop_column_group_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102819; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102819
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.drop_column_group_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.drop_column_group_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102819; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.drop_column_group_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.drop_columns_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.drop_columns_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102820; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102820
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.drop_columns_from_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.drop_columns_from_flavor"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102820; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.drop_columns_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.obsolete_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.obsolete_flavor_definition"; nocase; isdataat:1075,relative; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102821; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102821
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.obsolete_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.obsolete_flavor_definition"; nocase; isdataat:1075,relative; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102821; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.obsolete_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.publish_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.publish_flavor_definition"; nocase; isdataat:1075,relative; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102822; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102822
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.publish_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.publish_flavor_definition"; nocase; isdataat:1075,relative; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102822; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.publish_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.purge_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.purge_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102823; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102823
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_fla_mas.purge_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_fla_mas.purge_flavor_definition"; nocase; fast_pattern:only; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102823; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_fla_mas.purge_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.alter_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.alter_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102827; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102827
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.alter_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.alter_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102827; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.alter_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.comment_on_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.comment_on_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102828; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102828
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.comment_on_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.comment_on_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102828; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.comment_on_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.comment_on_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.comment_on_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102829; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102829
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.comment_on_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.comment_on_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102829; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.comment_on_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.create_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.create_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102831; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102831
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.create_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.create_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102831; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.create_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.do_deferred_repcat_admin buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.do_deferred_repcat_admin"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102832; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102832
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.do_deferred_repcat_admin buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.do_deferred_repcat_admin"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102832; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.do_deferred_repcat_admin buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.drop_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.drop_master_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102833; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102833
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.drop_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.drop_master_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102833; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.drop_master_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.generate_replication_package buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.generate_replication_package"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102834; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102834
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.generate_replication_package buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.generate_replication_package"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102834; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.generate_replication_package buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.purge_master_log buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.purge_master_log"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102835; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102835
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.purge_master_log buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.purge_master_log"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102835; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.purge_master_log buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.relocate_masterdef buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.relocate_masterdef"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102836; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102836
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.relocate_masterdef buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.relocate_masterdef"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102836; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.relocate_masterdef buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.rename_shadow_column_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.rename_shadow_column_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102837; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102837
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.rename_shadow_column_group buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.rename_shadow_column_group"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102837; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.rename_shadow_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.resume_master_activity buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.resume_master_activity"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102838; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102838
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.resume_master_activity buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.resume_master_activity"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102838; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.resume_master_activity buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.suspend_master_activity buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.suspend_master_activity"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102839; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102839
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.suspend_master_activity buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.suspend_master_activity"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102839; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_mas.suspend_master_activity buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_rq.add_column buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_rq.add_column"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*SCHEMA_NAME[\r\n\s]*=>[\r\n\s]*\2|SCHEMA_NAME\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102685; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102685
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_rq.add_column buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_rq.add_column"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*SCHEMA_NAME[\r\n\s]*=>[\r\n\s]*\2|SCHEMA_NAME\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102685; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_rq.add_column buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.alter_snapshot_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102902; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102902
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.alter_snapshot_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102902; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.alter_snapshot_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102903; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102903
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102903; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.create_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){7}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102904; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102904
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){7}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102904; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.create_snapshot_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102905; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102905
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.create_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.create_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102905; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.create_snapshot_repschema buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102906; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102906
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102906; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.drop_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102907; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102907
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102907; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.drop_snapshot_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102908; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102908
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.drop_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.drop_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102908; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.drop_snapshot_repschema buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.generate_snapshot_support buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.generate_snapshot_support"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102909; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102909
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.generate_snapshot_support buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.generate_snapshot_support"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102909; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.generate_snapshot_support buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.refresh_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102910; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102910
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.refresh_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102910; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.refresh_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.refresh_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.refresh_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102911; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102911
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.refresh_snapshot_repschema buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.refresh_snapshot_repschema"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102911; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.refresh_snapshot_repschema buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102912; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102912
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102912; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.register_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.repcat_import_check"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102913; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102913
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.repcat_import_check"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102913; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.repcat_import_check buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.set_local_flavor"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102914; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102914
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.set_local_flavor"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102914; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.set_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.switch_snapshot_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102915; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102915
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.switch_snapshot_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102915; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.switch_snapshot_master buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.unregister_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102916; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102916
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.unregister_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102916; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.unregister_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.validate_for_local_flavor"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102918; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102918
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna.validate_for_local_flavor"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102918; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna.validate_for_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.alter_snapshot_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102840; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102840
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.alter_snapshot_propagation"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102840; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.alter_snapshot_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.create_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102841; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102841
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.create_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102841; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.drop_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102842; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102842
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.drop_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102842; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.drop_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.drop_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102843; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102843
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.drop_snapshot_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102843; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.drop_snapshot_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.refresh_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102844; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102844
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.refresh_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102844; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.refresh_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102845; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102845
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102845; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.register_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.repcat_import_check"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102846; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102846
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.repcat_import_check"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102846; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.repcat_import_check buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.switch_snapshot_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102917; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102917
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.switch_snapshot_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102917; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.switch_snapshot_master buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.unregister_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102847; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102847
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_sna_utl.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_sna_utl.unregister_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102847; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_sna_utl.unregister_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_untrusted.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_untrusted.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102919; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102919
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_untrusted.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_untrusted.register_snapshot_repgroup"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102919; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_untrusted.register_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl.drop_an_object buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl.drop_an_object"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102849; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102849
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl.drop_an_object buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl.drop_an_object"; nocase; fast_pattern:only; pcre:"/(\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102849; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_utl.drop_an_object buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl.is_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl.is_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*CANON_GNAME[\r\n\s]*=>[\r\n\s]*\2|CANON_GNAME\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102696; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102696
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl.is_master buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl.is_master"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*CANON_GNAME[\r\n\s]*=>[\r\n\s]*\2|CANON_GNAME\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102696; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_utl.is_master buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl4.drop_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl4.drop_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102848; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102848
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_utl4.drop_master_repobject buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_utl4.drop_master_repobject"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102848; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_utl4.drop_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_system.ksdwrt buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_system.ksdwrt"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*tst[\r\n\s]*=>[\r\n\s]*\2|tst\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*\d+\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102679; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102679
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_system.ksdwrt buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_system.ksdwrt"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*tst[\r\n\s]*=>[\r\n\s]*\2|tst\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*\d+\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102679; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_system.ksdwrt buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.ltutil.pushdeferredtxns buffer overflow attempt"; flow:to_server,established; content:"sys.ltutil.pushdeferredtxns"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{512,}\x27|\x22[^\x22]{512,}\x22)[\r\n\s]*\x3b.*repgrpname[\r\n\s]*=>[\r\n\s]*\2|repgrpname\s*=>\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,})|\(\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,}))/si"; classtype:attempted-user; sid:2102684; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102684
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.ltutil.pushdeferredtxns buffer overflow attempt"; flow:to_server,established; content:"sys.ltutil.pushdeferredtxns"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{512,}\x27|\x22[^\x22]{512,}\x22)[\r\n\s]*\x3b.*repgrpname[\r\n\s]*=>[\r\n\s]*\2|repgrpname\s*=>\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,})|\(\s*(\x27[^\x27]{512,}|\x22[^\x22]{512,}))/si"; classtype:attempted-user; sid:2102684; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.ltutil.pushdeferredtxns buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sysdbms_repcat_rgt.check_ddl_text buffer overflow attempt"; flow:to_server,established; content:"sysdbms_repcat_rgt.check_ddl_text"; nocase; isdataat:1024,relative; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102608; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102608
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sysdbms_repcat_rgt.check_ddl_text buffer overflow attempt"; flow:to_server,established; content:"sysdbms_repcat_rgt.check_ddl_text"; nocase; isdataat:1024,relative; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102608; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sysdbms_repcat_rgt.check_ddl_text buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL time_zone buffer overflow attempt"; flow:to_server,established; content:"TIME_ZONE"; nocase; isdataat:1000,relative; pcre:"/TIME_ZONE\s*=\s*((\x27[^\x27]{1000,})|(\x22[^\x22]{1000,}))/msi"; reference:bugtraq,9587; reference:url,www.nextgenss.com/advisories/ora_time_zone.txt; classtype:attempted-user; sid:2102614; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102614
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL time_zone buffer overflow attempt"; flow:to_server,established; content:"TIME_ZONE"; nocase; isdataat:1000,relative; pcre:"/TIME_ZONE\s*=\s*((\x27[^\x27]{1000,})|(\x22[^\x22]{1000,}))/msi"; reference:bugtraq,9587; reference:url,www.nextgenss.com/advisories/ora_time_zone.txt; classtype:attempted-user; sid:2102614; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **time_zone buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : bugtraq,9587|url,www.nextgenss.com/advisories/ora_time_zone.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL user name buffer overflow attempt"; flow:to_server,established; content:"connect_data"; nocase; content:"|28|user="; nocase; isdataat:1000,relative; content:!"|22|"; within:1000; reference:url,www.appsecinc.com/Policy/PolicyCheck62.html; classtype:attempted-user; sid:2102650; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102650
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL user name buffer overflow attempt"; flow:to_server,established; content:"connect_data"; nocase; content:"|28|user="; nocase; isdataat:1000,relative; content:!"|22|"; within:1000; reference:url,www.appsecinc.com/Policy/PolicyCheck62.html; classtype:attempted-user; sid:2102650; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **user name buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck62.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL xp_cmdshell program execution"; flow:to_server,established; content:"x|00|p|00|_|00|c|00|m|00|d|00|s|00|h|00|e|00|l|00|l|00|"; offset:32; nocase; classtype:attempted-user; sid:2100681; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100681
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 139 (msg:"GPL SQL xp_cmdshell program execution"; flow:to_server,established; content:"x|00|p|00|_|00|c|00|m|00|d|00|s|00|h|00|e|00|l|00|l|00|"; offset:32; nocase; classtype:attempted-user; sid:2100681; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **xp_cmdshell program execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_start_job - program execution"; flow:to_server,established; content:"s|00|p|00|_|00|s|00|t|00|a|00|r|00|t|00|_|00|j|00|o|00|b|00|"; nocase; classtype:attempted-user; sid:2100673; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100673
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SQL sp_start_job - program execution"; flow:to_server,established; content:"s|00|p|00|_|00|s|00|t|00|a|00|r|00|t|00|_|00|j|00|o|00|b|00|"; nocase; classtype:attempted-user; sid:2100673; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sp_start_job - program execution** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102860; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102860
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_date buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_date"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102860; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.add_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_nvarchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102892; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102892
`#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_nvarchar2"; nocase; fast_pattern:only; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102892; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_nvarchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL add_grouped_column ordered sname/oname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_grouped_column"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22 ]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102600; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102600
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL add_grouped_column ordered sname/oname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_grouped_column"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22 ]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102600; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **add_grouped_column ordered sname/oname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck633.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_master_repgroup ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repgroup"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck87.html; classtype:attempted-user; sid:2102602; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102602
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_master_repgroup ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repgroup"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck87.html; classtype:attempted-user; sid:2102602; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **drop_master_repgroup ordered gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck87.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL create_mview_repgroup ordered fname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){4}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102604; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102604
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL create_mview_repgroup ordered fname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){4}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102604; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **create_mview_repgroup ordered fname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck633.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL comment_on_repobject ordered type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repobject"; nocase; pcre:"/\((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){2}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rsmi"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102607; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102607
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL comment_on_repobject ordered type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repobject"; nocase; pcre:"/\((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){2}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rsmi"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102607; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **comment_on_repobject ordered type buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck634.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL cancel_statistics ordered sname/oname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.cancel_statistics"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102610; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102610
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL cancel_statistics ordered sname/oname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.cancel_statistics"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102610; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **cancel_statistics ordered sname/oname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck633.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL grant_surrogate_repcat ordered userid buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_auth.grant_surrogate_repcat"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102616; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102616
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL grant_surrogate_repcat ordered userid buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_auth.grant_surrogate_repcat"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102616; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **grant_surrogate_repcat ordered userid buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL alter_mview_propagation ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_mview_propagation"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102618; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102618
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL alter_mview_propagation ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_mview_propagation"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102618; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **alter_mview_propagation ordered gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL unregister_user_repgroup ordered privilege_type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.unregister_user_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102625; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102625
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL unregister_user_repgroup ordered privilege_type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.unregister_user_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102625; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unregister_user_repgroup ordered privilege_type buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck94.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL repcat_import_check ordered gowner/gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.repcat_import_check"; nocase; pcre:"/\((\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102628; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102628
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL repcat_import_check ordered gowner/gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.repcat_import_check"; nocase; pcre:"/\((\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))|\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102628; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **repcat_import_check ordered gowner/gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL register_user_repgroup ordered privilege_type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.register_user_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102630; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102630
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL register_user_repgroup ordered privilege_type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.register_user_repgroup"; nocase; pcre:"/\(((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000})))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102630; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **register_user_repgroup ordered privilege_type buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck94.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL refresh_mview_repgroup ordered gowner buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_mview_repgroup"; nocase; pcre:"/\(\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,(\s*(true|false)\s*,\s*){3}((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102632; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102632
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL refresh_mview_repgroup ordered gowner buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_mview_repgroup"; nocase; pcre:"/\(\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,(\s*(true|false)\s*,\s*){3}((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102632; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **refresh_mview_repgroup ordered gowner buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL rectifier_diff ordered sname1 buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102634; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102634
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL rectifier_diff ordered sname1 buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102634; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **rectifier_diff ordered sname1 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL snapshot.end_load ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.end_load"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102636; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102636
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL snapshot.end_load ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.end_load"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102636; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **snapshot.end_load ordered gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_master_repobject ordered type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repobject"; nocase; pcre:"/\((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){2}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rsmi"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102638; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102638
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_master_repobject ordered type buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repobject"; nocase; pcre:"/\((\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,){2}\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rsmi"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102638; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **drop_master_repobject ordered type buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck634.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_mview_repgroup ordered gowner/gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repgroup"; nocase; pcre:"/\(\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102640; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102640
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_mview_repgroup ordered gowner/gname buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repgroup"; nocase; pcre:"/\(\s*(\x27[^\x27]*'|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102640; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **drop_mview_repgroup ordered gowner/gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_site_instantiate ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"drop_site_instantiation"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck629.html; classtype:attempted-user; sid:2102642; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102642
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL drop_site_instantiate ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"drop_site_instantiation"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck629.html; classtype:attempted-user; sid:2102642; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **drop_site_instantiate ordered refresh_template_name buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck629.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL from_tz buffer overflow attempt"; flow:to_server,established; content:"FROM_TZ"; nocase; pcre:"/\(\s*TIMESTAMP\s*(\s*(\x27[^\x27]+'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.nextgenss.com/advisories/ora_from_tz.txt; classtype:attempted-user; sid:2102644; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102644
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL from_tz buffer overflow attempt"; flow:to_server,established; content:"FROM_TZ"; nocase; pcre:"/\(\s*TIMESTAMP\s*(\s*(\x27[^\x27]+'|\x22[^\x22]+\x22)\s*,)\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.nextgenss.com/advisories/ora_from_tz.txt; classtype:attempted-user; sid:2102644; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **from_tz buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.nextgenss.com/advisories/ora_from_tz.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL instantiate_offline ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"instantiate_offline"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck630.html; classtype:attempted-user; sid:2102646; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102646
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL instantiate_offline ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"instantiate_offline"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck630.html; classtype:attempted-user; sid:2102646; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **instantiate_offline ordered refresh_template_name buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck630.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL instantiate_online ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"instantiate_online"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck631.html; classtype:attempted-user; sid:2102648; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102648
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL instantiate_online ordered refresh_template_name buffer overflow attempt"; flow:to_server,established; content:"instantiate_online"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck631.html; classtype:attempted-user; sid:2102648; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **instantiate_online ordered refresh_template_name buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck631.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL og.begin_load ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_load"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102653; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102653
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL og.begin_load ordered gname buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_load"; nocase; pcre:"/\(\s*((\x27[^\x27]{1000})|(\x22[^\x22]{1000}))/Rmsi"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102653; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **og.begin_load ordered gname buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SQL MySQL mysql.user Dump (Used in Metasploit Auth-Bypass Module)"; flow:established,to_server; content:"SELECT|20|user|2c|password|20|from|20|mysql|2e|user"; classtype:bad-unknown; sid:2014910; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_06_15, updated_at 2016_07_01;)

# 2014910
`alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SQL MySQL mysql.user Dump (Used in Metasploit Auth-Bypass Module)"; flow:established,to_server; content:"SELECT|20|user|2c|password|20|from|20|mysql|2e|user"; classtype:bad-unknown; sid:2014910; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_06_15, updated_at 2016_07_01;)
` 

Name : **MySQL mysql.user Dump (Used in Metasploit Auth-Bypass Module)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-06-15

Last modified date : 2016-07-01

Rev version : 3

Category : SQL

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_grouped_column buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_grouped_column"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102599; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102599
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_grouped_column buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_grouped_column"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102599; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_grouped_column buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SQL Oracle iSQLPlus login.uix username overflow attempt"; flow:to_server,established; content:"/login.uix"; fast_pattern; http_uri; nocase; content:"username="; nocase; isdataat:250,relative; content:!"|0A|"; within:250; pcre:"/username=[^&\x3b\r\n]{250}/smi"; reference:bugtraq,10871; reference:url,www.nextgenss.com/advisories/ora-isqlplus.txt; classtype:web-application-attack; sid:2102703; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102703
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL SQL Oracle iSQLPlus login.uix username overflow attempt"; flow:to_server,established; content:"/login.uix"; fast_pattern; http_uri; nocase; content:"username="; nocase; isdataat:250,relative; content:!"|0A|"; within:250; pcre:"/username=[^&\x3b\r\n]{250}/smi"; reference:bugtraq,10871; reference:url,www.nextgenss.com/advisories/ora-isqlplus.txt; classtype:web-application-attack; sid:2102703; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **Oracle iSQLPlus login.uix username overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,10871|url,www.nextgenss.com/advisories/ora-isqlplus.txt

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL ctx_output.start_log buffer overflow attempt"; flow:to_server,established; content:"ctx_output.start_log"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*logfile[\r\n\s]*=>[\r\n\s]*\2|logfile\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102678; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102678
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL ctx_output.start_log buffer overflow attempt"; flow:to_server,established; content:"ctx_output.start_log"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*logfile[\r\n\s]*=>[\r\n\s]*\2|logfile\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102678; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **ctx_output.start_log buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL alter file buffer overflow attempt"; flow:to_server,established; content:"alter"; nocase; fast_pattern; pcre:"/ALTER\s.*?FILE\s+((AS|MEMBER|TO)\s+)?(\x27[^\x27]{512}|\x22[^\x22]{512})/smi"; classtype:attempted-user; sid:2102697; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102697
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL alter file buffer overflow attempt"; flow:to_server,established; content:"alter"; nocase; fast_pattern; pcre:"/ALTER\s.*?FILE\s+((AS|MEMBER|TO)\s+)?(\x27[^\x27]{512}|\x22[^\x22]{512})/smi"; classtype:attempted-user; sid:2102697; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **alter file buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102708; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102708
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102708; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.begin_flavor_change buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102709; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102709
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102709; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.begin_instantiation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102652; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102652
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.begin_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.begin_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102652; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.begin_load buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102711; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102711
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102711; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.end_flavor_change buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102712; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102712
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102712; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.end_instantiation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102713; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102713
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.end_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.end_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102713; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.end_load buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.resume_subset_of_masters buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.resume_subset_of_masters"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102714; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102714
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_og.resume_subset_of_masters buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_og.resume_subset_of_masters"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102714; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_og.resume_subset_of_masters buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_snapshot.begin_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.begin_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102715; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102715
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_snapshot.begin_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.begin_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102715; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_snapshot.begin_load buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_snapshot.end_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.end_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102635; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102635
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_offline_snapshot.end_load buffer overflow attempt"; flow:to_server,established; content:"dbms_offline_snapshot.end_load"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck632.html; classtype:attempted-user; sid:2102635; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_offline_snapshot.end_load buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck632.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_rectifier_diff.differences buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff.differences"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(missing_rows_oname1|missing_rows_oname2)[\r\n\s]*=>[\r\n\s]*\2|(missing_rows_oname1|missing_rows_oname2)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){10}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102717; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102717
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_rectifier_diff.differences buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff.differences"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(missing_rows_oname1|missing_rows_oname2)[\r\n\s]*=>[\r\n\s]*\2|(missing_rows_oname1|missing_rows_oname2)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){10}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102717; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_rectifier_diff.differences buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_rectifier_diff.rectify buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff.rectify"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(missing_rows_oname1|missing_rows_oname2)[\r\n\s]*=>[\r\n\s]*\2|(missing_rows_oname1|missing_rows_oname2)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){8}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102718; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102718
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_rectifier_diff.rectify buffer overflow attempt"; flow:to_server,established; content:"dbms_rectifier_diff.rectify"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(missing_rows_oname1|missing_rows_oname2)[\r\n\s]*=>[\r\n\s]*\2|(missing_rows_oname1|missing_rows_oname2)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){8}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){9}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102718; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_rectifier_diff.rectify buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.abort_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.abort_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102719; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102719
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.abort_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.abort_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102719; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.abort_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_column_group_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_column_group_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102720; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102720
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_column_group_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_column_group_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102720; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_column_group_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_columns_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_columns_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102721; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102721
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_columns_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_columns_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102721; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_columns_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102674; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102674
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102674; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_object_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_object_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102722; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102722
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_object_to_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_object_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102722; rev:3; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_object_to_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 3

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102723; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102723
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102723; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102724; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102724
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102724; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102725; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102725
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102725; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102727; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102727
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102727; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_nvarchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102728; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102728
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102728; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102729; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102729
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102729; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102730; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102730
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102730; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102731; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102731
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102731; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102732; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102732
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.add_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102732; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.add_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_master_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_master_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102733; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102733
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_master_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_master_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102733; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_master_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102619; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102619
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102619; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck634.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_mview_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_mview_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102734; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102734
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_mview_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_mview_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){3}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102734; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_mview_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102741; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102741
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102741; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102735; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102735
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102735; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102736; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102736
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102736; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102737; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102737
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102737; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_number buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_number"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102738; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102738
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_number buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_number"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102738; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_number buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102739; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102739
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102739; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_nvarchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102740; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102740
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102740; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102742; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102742
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102742; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102744; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102744
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102744; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102743; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102743
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102743; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_snapshot_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102745; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102745
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.alter_snapshot_propagation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.alter_snapshot_propagation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102745; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.alter_snapshot_propagation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.begin_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.begin_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102747; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102747
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.begin_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.begin_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102747; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.begin_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.cancel_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.cancel_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102609; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102609
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.cancel_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.cancel_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*sname[\r\n\s]*=>[\r\n\s]*\2|sname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*oname[\r\n\s]*=>[\r\n\s]*\2|oname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102609; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.cancel_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102748; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102748
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102748; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102749; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102749
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102749; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_mview_repsites buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_mview_repsites"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gowner|gname)[\r\n\s]*=>[\r\n\s]*\2|(gowner|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102750; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102750
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_mview_repsites buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_mview_repsites"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gowner|gname)[\r\n\s]*=>[\r\n\s]*\2|(gowner|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102750; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_mview_repsites buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_priority_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_priority_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102751; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102751
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_priority_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_priority_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102751; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_priority_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102752; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102752
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102752; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102606; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102606
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102606; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck634.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repsites buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repsites"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102753; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102753
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_repsites buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_repsites"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102753; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_repsites buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102754; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102754
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102754; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102755; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102755
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102755; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102756; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102756
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.comment_on_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.comment_on_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102756; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.comment_on_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.compare_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.compare_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*operation[\r\n\s]*=>[\r\n\s]*\2|operation\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck91.html; classtype:attempted-user; sid:2102605; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102605
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.compare_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.compare_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*operation[\r\n\s]*=>[\r\n\s]*\2|operation\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck91.html; classtype:attempted-user; sid:2102605; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.compare_old_values buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck91.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102757; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102757
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102757; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_master_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102758; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102758
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102758; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*fname[\r\n\s]*=>[\r\n\s]*\2|fname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102603; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102603
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*fname[\r\n\s]*=>[\r\n\s]*\2|fname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck633.html; classtype:attempted-user; sid:2102603; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_mview_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck633.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_mview_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){7}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102850; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102850
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_mview_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_mview_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){7}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102850; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_mview_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102759; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102759
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102759; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_snapshot_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102851; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102851
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.create_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.create_snapshot_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type|gname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){5}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102851; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.create_snapshot_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102760; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102760
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102760; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.define_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_priority_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_priority_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102761; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102761
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_priority_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_priority_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102761; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.define_priority_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102762; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102762
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.define_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.define_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102762; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.define_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.do_deferred_repcat_admin buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.do_deferred_repcat_admin"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102763; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102763
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.do_deferred_repcat_admin buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.do_deferred_repcat_admin"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102763; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.do_deferred_repcat_admin buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_column_group_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_column_group_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102764; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102764
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_column_group_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_column_group_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102764; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_column_group_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102765; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102765
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102765; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_columns_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_columns_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102766; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102766
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_columns_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_columns_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102766; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_columns_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102767; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102767
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_delete_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_delete_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102767; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_delete_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102601; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102601
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102601; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_master_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102637; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102637
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_master_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_master_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*type[\r\n\s]*=>[\r\n\s]*\2|type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck634.html; classtype:attempted-user; sid:2102637; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_master_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck634.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102639; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102639
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102639; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_mview_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_mview_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102769; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102769
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_mview_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_mview_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102769; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_mview_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_object_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_object_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102770; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102770
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_object_from_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_object_from_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102770; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_object_from_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102777; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102777
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102777; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102771; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102771
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_char buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102771; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102779; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102779
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102779; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102772; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102772
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_date buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_date"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102772; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_date buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102773; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102773
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_nchar buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_nchar"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102773; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_nchar buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_number buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_number"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102774; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102774
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_number buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_number"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102774; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_number buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102775; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102775
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_nvarchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_nvarchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102775; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_nvarchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102776; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102776
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_raw buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102776; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102778; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102778
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102778; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102780; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102780
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_site_priority buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_site_priority"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102780; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_site_priority buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102781; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102781
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102781; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_snapshot_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102782; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102782
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_snapshot_repobject buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_snapshot_repobject"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102782; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_snapshot_repobject buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102783; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102783
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_unique_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_unique_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102783; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_unique_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102784; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102784
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.drop_update_resolution buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.drop_update_resolution"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102784; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.drop_update_resolution buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.execute_ddl buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.execute_ddl"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102785; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102785
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.execute_ddl buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.execute_ddl"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102785; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.execute_ddl buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_mview_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_mview_support"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102852; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102852
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_mview_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_mview_support"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102852; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.generate_mview_support buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_package buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_package"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102786; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102786
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_package buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_package"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102786; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.generate_replication_package buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_trigger buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_trigger"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|gname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102853; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102853
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_replication_trigger buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_replication_trigger"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|gname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|gname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102853; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.generate_replication_trigger buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_snapshot_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_snapshot_support"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102854; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102854
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.generate_snapshot_support buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.generate_snapshot_support"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname|type)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname|type)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102854; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.generate_snapshot_support buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.make_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.make_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102788; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102788
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.make_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.make_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102788; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.make_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.obsolete_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.obsolete_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102789; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102789
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.obsolete_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.obsolete_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102789; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.obsolete_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.publish_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.publish_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102790; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102790
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.publish_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.publish_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102790; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.publish_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102791; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102791
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102791; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.purge_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_master_log buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_master_log"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102792; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102792
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_master_log buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_master_log"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102792; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.purge_master_log buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102793; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102793
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.purge_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.purge_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102793; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.purge_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.refresh_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102631; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102631
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.refresh_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102631; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.refresh_mview_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102795; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102795
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.refresh_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.refresh_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102795; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.refresh_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102796; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102796
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){4}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102796; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.register_mview_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102797; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102797
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102797; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.register_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102798; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102798
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.register_statistics buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.register_statistics"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102798; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.register_statistics buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.relocate_masterdef buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.relocate_masterdef"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102799; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102799
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.relocate_masterdef buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.relocate_masterdef"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102799; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.relocate_masterdef buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.remove_master_databases buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.remove_master_databases"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102855; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102855
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.remove_master_databases buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.remove_master_databases"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102855; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.remove_master_databases buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.rename_shadow_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.rename_shadow_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102800; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102800
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.rename_shadow_column_group buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.rename_shadow_column_group"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102800; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.rename_shadow_column_group buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.repcat_import_check"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102627; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102627
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.repcat_import_check buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.repcat_import_check"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|(\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*gowner[\r\n\s]*=>[\r\n\s]*\2|gowner\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(true|false)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck90.html; classtype:attempted-user; sid:2102627; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.repcat_import_check buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck90.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.resume_master_activity buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.resume_master_activity"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102801; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102801
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.resume_master_activity buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.resume_master_activity"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102801; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.resume_master_activity buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.send_and_compare_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.send_and_compare_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102804; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102804
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.send_and_compare_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.send_and_compare_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102804; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.send_and_compare_old_values buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.send_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.send_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*operation[\r\n\s]*=>[\r\n\s]*\2|operation\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck91.html; classtype:attempted-user; sid:2102626; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102626
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.send_old_values buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.send_old_values"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*operation[\r\n\s]*=>[\r\n\s]*\2|operation\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck91.html; classtype:attempted-user; sid:2102626; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.send_old_values buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck91.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.set_columns buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.set_columns"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102805; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102805
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.set_columns buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.set_columns"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(sname|oname)[\r\n\s]*=>[\r\n\s]*\2|(sname|oname)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102805; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.set_columns buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.set_local_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102806; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102806
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.set_local_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.set_local_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|fname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|fname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102806; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.set_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.specify_new_masters buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.specify_new_masters"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102807; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102807
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.specify_new_masters buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.specify_new_masters"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102807; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.specify_new_masters buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.suspend_master_activity buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.suspend_master_activity"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102808; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102808
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.suspend_master_activity buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.suspend_master_activity"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102808; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.suspend_master_activity buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.switch_mview_master buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.switch_mview_master"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102856; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102856
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.switch_mview_master buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.switch_mview_master"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102856; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.switch_mview_master buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.switch_snapshot_master"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1073,}\x27|\x22[^\x22]{1073,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1073,}|\x22[^\x22]{1073,})|\(\s*(\x27[^\x27]{1073,}|\x22[^\x22]{1073,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102857; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102857
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.switch_snapshot_master buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.switch_snapshot_master"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1073,}\x27|\x22[^\x22]{1073,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1073,}|\x22[^\x22]{1073,})|\(\s*(\x27[^\x27]{1073,}|\x22[^\x22]{1073,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102857; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.switch_snapshot_master buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.unregister_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.unregister_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102809; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102809
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.unregister_mview_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.unregister_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102809; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.unregister_mview_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.unregister_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102810; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102810
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.unregister_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.unregister_snapshot_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102810; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.unregister_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.validate_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.validate_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102811; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102811
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.validate_flavor_definition buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.validate_flavor_definition"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102811; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.validate_flavor_definition buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.validate_for_local_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102812; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102812
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.validate_for_local_flavor buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat.validate_for_local_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102812; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat.validate_for_local_flavor buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_admin.register_user_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.register_user_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102629; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102629
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_admin.register_user_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.register_user_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102629; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_admin.register_user_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck94.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_admin.unregister_user_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.unregister_user_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102624; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102624
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_admin.unregister_user_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_admin.unregister_user_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck94.html; classtype:attempted-user; sid:2102624; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_admin.unregister_user_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck94.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_auth.revoke_surrogate_repcat"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102746; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102746
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_auth.revoke_surrogate_repcat"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*userid[\r\n\s]*=>[\r\n\s]*\2|userid\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102746; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_auth.revoke_surrogate_repcat buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.drop_site_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.drop_site_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102641; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102641
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.drop_site_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.drop_site_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102641; rev:6; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_instantiate.drop_site_instantiation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 6

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.instantiate_offline buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.instantiate_offline"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102645; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102645
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.instantiate_offline buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.instantiate_offline"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102645; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_instantiate.instantiate_offline buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.instantiate_online buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.instantiate_online"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102647; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102647
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_instantiate.instantiate_online buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_instantiate.instantiate_online"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102647; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_instantiate.instantiate_online buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.check_ddl_text buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.check_ddl_text"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(object_type|user_name)[\r\n\s]*=>[\r\n\s]*\2|(object_type|user_name)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102802; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102802
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.check_ddl_text buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.check_ddl_text"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(object_type|user_name)[\r\n\s]*=>[\r\n\s]*\2|(object_type|user_name)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102802; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_rgt.check_ddl_text buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.drop_site_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.drop_site_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102676; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102676
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.drop_site_instantiation buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.drop_site_instantiation"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102676; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_rgt.drop_site_instantiation buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.instantiate_offline buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.instantiate_offline"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102675; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102675
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.instantiate_offline buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.instantiate_offline"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*privilege_type[\r\n\s]*=>[\r\n\s]*\2|privilege_type\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102675; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_rgt.instantiate_offline buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.instantiate_online buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.instantiate_online"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102677; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102677
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_rgt.instantiate_online buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_rgt.instantiate_online"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1024,}\x27|\x22[^\x22]{1024,}\x22)[\r\n\s]*\x3b.*refresh_template_name[\r\n\s]*=>[\r\n\s]*\2|refresh_template_name\s*=>\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1024,}|\x22[^\x22]{1024,}))/si"; classtype:attempted-user; sid:2102677; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_rgt.instantiate_online buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_sna_utl.create_snapshot_repgroup"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102623; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102623
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_sna_utl.create_snapshot_repgroup"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102623; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_sna_utl.create_snapshot_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_sna_utl.register_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_sna_utl.register_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102621; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102621
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_sna_utl.register_flavor_change buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_sna_utl.register_flavor_change"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102621; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_sna_utl.register_flavor_change buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_utl.drop_an_object buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_utl.drop_an_object"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102622; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102622
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat_utl.drop_an_object buffer overflow attempt"; flow:to_server,established; content:"dbms_repcat_utl.drop_an_object"; nocase; fast_pattern; pcre:"/\(\s*(\x27[^\x27]{1024,}|\x22[^\x22]{1024,})/si"; reference:url,www.appsecinc.com/Policy/PolicyCheck97.html; classtype:attempted-user; sid:2102622; rev:5; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **dbms_repcat_utl.drop_an_object buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/Policy/PolicyCheck97.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 5

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102859; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102859
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.add_priority_char buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.add_priority_char"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102859; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **sys.dbms_repcat_conf.add_priority_char buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102877; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102877
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.alter_site_priority_site buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.alter_site_priority_site"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102877; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **sys.dbms_repcat_conf.alter_site_priority_site buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102893; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102893
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_raw buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_raw"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102893; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_raw buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102895; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102895
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_conf.drop_priority_varchar2 buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_conf.drop_priority_varchar2"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102895; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **sys.dbms_repcat_conf.drop_priority_varchar2 buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.create_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.create_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102830; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2102830
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL sys.dbms_repcat_mas.create_master_repgroup buffer overflow attempt"; flow:to_server,established; content:"sys.dbms_repcat_mas.create_master_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102830; rev:4; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **sys.dbms_repcat_mas.create_master_repgroup buffer overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 4

Category : SQL

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



