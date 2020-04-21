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



alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET TELNET login failed"; flow:from_server,established; content:"Login failed"; nocase; classtype:bad-unknown; sid:2100492; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100492
`alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET TELNET login failed"; flow:from_server,established; content:"Login failed"; nocase; classtype:bad-unknown; sid:2100492; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TELNET login failed** 

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

Category : TELNET

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET TELNET access"; flow:from_server,established; content:"|FF FD|"; rawbytes; content:"|FF FD|"; distance:0; rawbytes; content:"|FF FD|"; distance:0; rawbytes; reference:arachnids,08; reference:cve,1999-0619; reference:nessus,10280; classtype:not-suspicious; sid:2100716; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100716
`#alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET TELNET access"; flow:from_server,established; content:"|FF FD|"; rawbytes; content:"|FF FD|"; distance:0; rawbytes; content:"|FF FD|"; distance:0; rawbytes; reference:arachnids,08; reference:cve,1999-0619; reference:nessus,10280; classtype:not-suspicious; sid:2100716; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TELNET access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : arachnids,08|cve,1999-0619|nessus,10280

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : TELNET

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET TELNET External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Dissalowed Until Password Set)"; flow:from_server; content:"Password required, but none set"; depth:31; reference:url,doc.emergingthreats.net/bin/view/Main/2008860; classtype:attempted-admin; sid:2008860; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008860
`alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET TELNET External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Dissalowed Until Password Set)"; flow:from_server; content:"Password required, but none set"; depth:31; reference:url,doc.emergingthreats.net/bin/view/Main/2008860; classtype:attempted-admin; sid:2008860; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **External Telnet Attempt To Cisco Device With No Telnet Password Set (Automatically Dissalowed Until Password Set)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008860

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : TELNET

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET TELNET External Telnet Login Prompt from Cisco Device"; flow:from_server,established; pcre:"/^(\r\n)*/"; content:"User Access Verification"; within:24; reference:url,doc.emergingthreats.net/bin/view/Main/2008861; classtype:attempted-admin; sid:2008861; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008861
`#alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"ET TELNET External Telnet Login Prompt from Cisco Device"; flow:from_server,established; pcre:"/^(\r\n)*/"; content:"User Access Verification"; within:24; reference:url,doc.emergingthreats.net/bin/view/Main/2008861; classtype:attempted-admin; sid:2008861; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **External Telnet Login Prompt from Cisco Device** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008861

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : TELNET

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS Path to BusyBox"; flow:to_server,established; content:"/bin/busybox"; flowbits:set,ET.telnet.busybox;threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:suspicious-filename-detect; sid:2023016; rev:1; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_08;)

# 2023016
`alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS Path to BusyBox"; flow:to_server,established; content:"/bin/busybox"; flowbits:set,ET.telnet.busybox;threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:suspicious-filename-detect; sid:2023016; rev:1; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_08;)
` 

Name : **SUSPICIOUS Path to BusyBox** 

Attack target : Server

Description : This signature triggers on BusyBox bruteforce attacks observed in the wild in August 2016. See the following for more info. http://lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-filename-detect

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2016-08-08

Last modified date : 2016-08-08

Rev version : 1

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox MIRAI hackers - Possible Brute Force Attack"; flow:to_server,established; content:"MIRAI"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023019; rev:2; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_09_26;)

# 2023019
`alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox MIRAI hackers - Possible Brute Force Attack"; flow:to_server,established; content:"MIRAI"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023019; rev:2; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_09_26;)
` 

Name : **busybox MIRAI hackers - Possible Brute Force Attack** 

Attack target : Server

Description : This signature triggers on BusyBox bruteforce attacks observed in the wild in August 2016. See the following for more info. http://lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2016-08-08

Last modified date : 2016-09-26

Rev version : 2

Category : TELNET

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox ECCHI hackers - Possible Brute Force Attack"; flow:to_server,established; content:"ECCHI"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023304; rev:1; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_09_27, performance_impact Low, updated_at 2016_09_27;)

# 2023304
`alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox ECCHI hackers - Possible Brute Force Attack"; flow:to_server,established; content:"ECCHI"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023304; rev:1; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_09_27, performance_impact Low, updated_at 2016_09_27;)
` 

Name : **busybox ECCHI hackers - Possible Brute Force Attack** 

Attack target : Server

Description : This signature triggers on BusyBox bruteforce attacks observed in the wild in August 2016. See the following for more info. http://lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2016-09-27

Last modified date : 2016-09-27

Rev version : 1

Category : TELNET

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox MEMES Hackers - Possible Brute Force Attack"; flow:to_server,established; content:"MEMES"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023901; rev:1; metadata:affected_product Linux, attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2017_02_14, malware_family Mirai, performance_impact Moderate, updated_at 2017_02_14;)

# 2023901
`alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox MEMES Hackers - Possible Brute Force Attack"; flow:to_server,established; content:"MEMES"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023901; rev:1; metadata:affected_product Linux, attack_target Networking_Equipment, deployment Perimeter, signature_severity Major, created_at 2017_02_14, malware_family Mirai, performance_impact Moderate, updated_at 2017_02_14;)
` 

Name : **busybox MEMES Hackers - Possible Brute Force Attack** 

Attack target : Networking_Equipment

Description : Not defined

Tags : Not defined

Affected products : Linux

Alert Classtype : attempted-admin

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2017-02-14

Last modified date : 2017-02-14

Rev version : 1

Category : TELNET

Severity : Major

Ruleset : ET

Malware Family : Mirai

Type : SID

Performance Impact : Moderate



#alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS busybox shell"; flow:to_server,established; content:"shell"; fast_pattern:only; pcre:"/\bshell\b/"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023017; rev:3; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_23;)

# 2023017
`#alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS busybox shell"; flow:to_server,established; content:"shell"; fast_pattern:only; pcre:"/\bshell\b/"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023017; rev:3; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_23;)
` 

Name : **SUSPICIOUS busybox shell** 

Attack target : Server

Description : This signature triggers on BusyBox bruteforce attacks observed in the wild in August 2016. See the following for more info. http://lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2016-08-08

Last modified date : 2016-08-23

Rev version : 3

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



#alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS busybox enable"; flow:to_server,established; content:"enable"; fast_pattern:only; pcre:"/\benable\b/"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023018; rev:4; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_23;)

# 2023018
`#alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET SUSPICIOUS busybox enable"; flow:to_server,established; content:"enable"; fast_pattern:only; pcre:"/\benable\b/"; flowbits:isset,ET.telnet.busybox; threshold: type limit, count 1, track by_src, seconds 30; metadata: former_category TELNET; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023018; rev:4; metadata:attack_target Server, deployment Datacenter, signature_severity Major, created_at 2016_08_08, performance_impact Low, updated_at 2016_08_23;)
` 

Name : **SUSPICIOUS busybox enable** 

Attack target : Server

Description : This signature triggers on BusyBox bruteforce attacks observed in the wild in August 2016. See the following for more info. http://lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html

CVE reference : Not defined

Creation date : 2016-08-08

Last modified date : 2016-08-23

Rev version : 4

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET Telnet Root not on console"; flow:from_server,established; content:"not on system console"; fast_pattern; nocase; reference:arachnids,365; classtype:bad-unknown; sid:2100717; rev:10; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2100717
`alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET Telnet Root not on console"; flow:from_server,established; content:"not on system console"; fast_pattern; nocase; reference:arachnids,365; classtype:bad-unknown; sid:2100717; rev:10; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **Telnet Root not on console** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,365

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 10

Category : TELNET

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET root login"; flow:from_server,established; content:"login|3a 20|root"; fast_pattern; classtype:suspicious-login; sid:2100719; rev:9; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2100719
`alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET root login"; flow:from_server,established; content:"login|3a 20|root"; fast_pattern; classtype:suspicious-login; sid:2100719; rev:9; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **root login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : suspicious-login

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 9

Category : TELNET

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"GPL TELNET Bad Login"; flow:from_server,established; content:"Login incorrect"; nocase; fast_pattern; classtype:bad-unknown; sid:2101251; rev:10; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101251
`alert tcp $HOME_NET 23 -> $EXTERNAL_NET any (msg:"GPL TELNET Bad Login"; flow:from_server,established; content:"Login incorrect"; nocase; fast_pattern; classtype:bad-unknown; sid:2101251; rev:10; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **Bad Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 10

Category : TELNET

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



