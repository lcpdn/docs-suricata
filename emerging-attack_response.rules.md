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



#alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET ATTACK_RESPONSE Cisco TclShell TFTP Read Request"; content:"|00 01 74 63 6C 73 68 2E 74 63 6C|"; reference:url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf; reference:url,doc.emergingthreats.net/2009244; classtype:bad-unknown; sid:2009244; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009244
`#alert udp $HOME_NET any -> $EXTERNAL_NET 69 (msg:"ET ATTACK_RESPONSE Cisco TclShell TFTP Read Request"; content:"|00 01 74 63 6C 73 68 2E 74 63 6C|"; reference:url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf; reference:url,doc.emergingthreats.net/2009244; classtype:bad-unknown; sid:2009244; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco TclShell TFTP Read Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf|url,doc.emergingthreats.net/2009244

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET 69 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Cisco TclShell TFTP Download"; content:"|54 63 6C 53 68 65 6C 6C|"; reference:url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf; reference:url,doc.emergingthreats.net/2009245; classtype:bad-unknown; sid:2009245; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009245
`alert udp $EXTERNAL_NET 69 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Cisco TclShell TFTP Download"; content:"|54 63 6C 53 68 65 6C 6C|"; reference:url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf; reference:url,doc.emergingthreats.net/2009245; classtype:bad-unknown; sid:2009245; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Cisco TclShell TFTP Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,wwww.irmplc.com/downloads/whitepapers/Creating_Backdoors_in_Cisco_IOS_using_Tcl.pdf|url,doc.emergingthreats.net/2009245

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM1"; flow: established; content:"/COM1/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000499; classtype:string-detect; sid:2000499; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000499
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM1"; flow: established; content:"/COM1/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000499; classtype:string-detect; sid:2000499; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access COM1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000499

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM2"; flow: established; content:"/COM2/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000500; classtype:string-detect; sid:2000500; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000500
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM2"; flow: established; content:"/COM2/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000500; classtype:string-detect; sid:2000500; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access COM2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000500

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM3"; flow: established; content:"/COM3/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000501; classtype:string-detect; sid:2000501; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000501
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM3"; flow: established; content:"/COM3/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000501; classtype:string-detect; sid:2000501; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access COM3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000501

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM4"; flow: established; content:"/COM4/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000502; classtype:string-detect; sid:2000502; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000502
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access COM4"; flow: established; content:"/COM4/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000502; classtype:string-detect; sid:2000502; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access COM4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000502

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT1"; flow: established; content:"/LPT1/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000503; classtype:string-detect; sid:2000503; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000503
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT1"; flow: established; content:"/LPT1/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000503; classtype:string-detect; sid:2000503; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access LPT1** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000503

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT2"; flow: established; content:"/LPT2/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000504; classtype:string-detect; sid:2000504; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000504
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT2"; flow: established; content:"/LPT2/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000504; classtype:string-detect; sid:2000504; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access LPT2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000504

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT3"; flow: established; content:"/LPT3/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000505; classtype:string-detect; sid:2000505; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000505
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT3"; flow: established; content:"/LPT3/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000505; classtype:string-detect; sid:2000505; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access LPT3** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000505

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT4"; flow: established; content:"/LPT4/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000506; classtype:string-detect; sid:2000506; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000506
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access LPT4"; flow: established; content:"/LPT4/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000506; classtype:string-detect; sid:2000506; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access LPT4** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000506

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access AUX"; flow: established; content:"/AUX/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000507; classtype:string-detect; sid:2000507; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000507
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access AUX"; flow: established; content:"/AUX/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000507; classtype:string-detect; sid:2000507; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access AUX** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000507

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access NULL"; flow: established; content:"/NULL/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000508; classtype:string-detect; sid:2000508; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000508
`alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET ATTACK_RESPONSE FTP inaccessible directory access NULL"; flow: established; content:"/NULL/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2000508; classtype:string-detect; sid:2000508; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP inaccessible directory access NULL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : string-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2000508

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - pass"; flowbits:isset,ET.strippedftpuser; flow:established,from_server; dsize:>7; content:"PASS "; depth:5; offset:0; content:" |0d 0a|"; distance:1; flowbits:set,ET.strippedftppass; reference:url,doc.emergingthreats.net/bin/view/Main/2007717; classtype:trojan-activity; sid:2007717; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007717
`#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - pass"; flowbits:isset,ET.strippedftpuser; flow:established,from_server; dsize:>7; content:"PASS "; depth:5; offset:0; content:" |0d 0a|"; distance:1; flowbits:set,ET.strippedftppass; reference:url,doc.emergingthreats.net/bin/view/Main/2007717; classtype:trojan-activity; sid:2007717; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Off-Port FTP Without Banners - pass** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007717

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - retr"; flowbits:isset,ET.strippedftppass; flow:established,from_server; dsize:>7; content:"RETR "; depth:5; offset:0; tag:session,300,seconds; reference:url,doc.emergingthreats.net/bin/view/Main/2007723; classtype:trojan-activity; sid:2007723; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007723
`#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - retr"; flowbits:isset,ET.strippedftppass; flow:established,from_server; dsize:>7; content:"RETR "; depth:5; offset:0; tag:session,300,seconds; reference:url,doc.emergingthreats.net/bin/view/Main/2007723; classtype:trojan-activity; sid:2007723; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Off-Port FTP Without Banners - retr** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007723

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (StnyFtpd)"; flow:established,from_server; content:"220 StnyFtpd 0wns j0"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002809; classtype:trojan-activity; sid:2002809; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002809
`alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (StnyFtpd)"; flow:established,from_server; content:"220 StnyFtpd 0wns j0"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002809; classtype:trojan-activity; sid:2002809; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Hostile FTP Server Banner (StnyFtpd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002809

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (Reptile)"; flow:established,from_server; content:"220 Reptile welcomes you"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002810; classtype:trojan-activity; sid:2002810; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002810
`alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (Reptile)"; flow:established,from_server; content:"220 Reptile welcomes you"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002810; classtype:trojan-activity; sid:2002810; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Hostile FTP Server Banner (Reptile)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002810

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (Bot Server)"; flow:established,from_server; content:"220 Bot Server (Win32)"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002811; classtype:trojan-activity; sid:2002811; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002811
`alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Hostile FTP Server Banner (Bot Server)"; flow:established,from_server; content:"220 Bot Server (Win32)"; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002811; classtype:trojan-activity; sid:2002811; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Hostile FTP Server Banner (Bot Server)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002811

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any [21,1024:] -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (fuckFtpd)"; flow:established,from_server; dsize:<18; content:"220 fuckFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/2009210; classtype:trojan-activity; sid:2009210; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009210
`alert tcp any [21,1024:] -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (fuckFtpd)"; flow:established,from_server; dsize:<18; content:"220 fuckFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/2009210; classtype:trojan-activity; sid:2009210; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner (fuckFtpd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009210

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any [21,1024:] -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (NzmxFtpd)"; flow:established,from_server; dsize:<18; content:"220 NzmxFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/2009211; classtype:trojan-activity; sid:2009211; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009211
`alert tcp any [21,1024:] -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (NzmxFtpd)"; flow:established,from_server; dsize:<18; content:"220 NzmxFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/2009211; classtype:trojan-activity; sid:2009211; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner (NzmxFtpd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2009211

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File Download Detected"; flow:to_client,established; content:"stdapi_fs_stat"; depth:54; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009558; classtype:successful-user; sid:2009558; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009558
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File Download Detected"; flow:to_client,established; content:"stdapi_fs_stat"; depth:54; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009558; classtype:successful-user; sid:2009558; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter File Download Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009558

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Process List (ps) Command Detected"; flow:to_client,established; content:"stdapi_sys_process_get_processes"; depth:65; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009559; classtype:successful-user; sid:2009559; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009559
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Process List (ps) Command Detected"; flow:to_client,established; content:"stdapi_sys_process_get_processes"; depth:65; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009559; classtype:successful-user; sid:2009559; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Process List (ps) Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009559

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Getuid Command Detected"; flow:to_client,established; content:"stdapi_sys_config_getuid"; depth:65; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009560; classtype:successful-user; sid:2009560; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009560
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Getuid Command Detected"; flow:to_client,established; content:"stdapi_sys_config_getuid"; depth:65; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009560; classtype:successful-user; sid:2009560; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Getuid Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009560

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Process Migration Detected"; flow:to_client,established; content:"core_migrate"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009561; classtype:successful-user; sid:2009561; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009561
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Process Migration Detected"; flow:to_client,established; content:"core_migrate"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009561; classtype:successful-user; sid:2009561; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Process Migration Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009561

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter ipconfig Command Detected"; flow:to_client,established; content:"stdapi_net_config_get_interfaces"; depth:65; threshold: type threshold, track by_src, count 2, seconds 4; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009562; classtype:successful-user; sid:2009562; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009562
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter ipconfig Command Detected"; flow:to_client,established; content:"stdapi_net_config_get_interfaces"; depth:65; threshold: type threshold, track by_src, count 2, seconds 4; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009562; classtype:successful-user; sid:2009562; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter ipconfig Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009562

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Sysinfo Command Detected"; flow:to_client,established; content:"stdapi_sys_config_sysinfo"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009563; classtype:successful-user; sid:2009563; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009563
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Sysinfo Command Detected"; flow:to_client,established; content:"stdapi_sys_config_sysinfo"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009563; classtype:successful-user; sid:2009563; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Sysinfo Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009563

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Route Command Detected"; flow:to_client,established; content:"stdapi_net_config_get_route"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009564; classtype:successful-user; sid:2009564; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009564
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Route Command Detected"; flow:to_client,established; content:"stdapi_net_config_get_route"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009564; classtype:successful-user; sid:2009564; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Route Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009564

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Kill Process Command Detected"; flow:to_client,established; content:"stdapi_sys_process_kill"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009565; classtype:successful-user; sid:2009565; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009565
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Kill Process Command Detected"; flow:to_client,established; content:"stdapi_sys_process_kill"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009565; classtype:successful-user; sid:2009565; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Kill Process Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009565

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Print Working Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_getwd"; depth:55; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009566; classtype:successful-user; sid:2009566; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009566
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Print Working Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_getwd"; depth:55; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009566; classtype:successful-user; sid:2009566; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Print Working Directory Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009566

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter View Current Process ID Command Detected"; flow:to_client,established; content:"stdapi_sys_process_getpid"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009567; classtype:successful-user; sid:2009567; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009567
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter View Current Process ID Command Detected"; flow:to_client,established; content:"stdapi_sys_process_getpid"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009567; classtype:successful-user; sid:2009567; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter View Current Process ID Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009567

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Execute Command Detected"; flow:to_client,established; content:"stdapi_sys_process_execute"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009568; classtype:successful-user; sid:2009568; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009568
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Execute Command Detected"; flow:to_client,established; content:"stdapi_sys_process_execute"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009568; classtype:successful-user; sid:2009568; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Execute Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009568

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter System Reboot/Shutdown Detected"; flow:to_client,established; content:"stdapi_sys_power_exitwindows"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009569; classtype:successful-user; sid:2009569; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009569
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter System Reboot/Shutdown Detected"; flow:to_client,established; content:"stdapi_sys_power_exitwindows"; depth:62; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009569; classtype:successful-user; sid:2009569; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter System Reboot/Shutdown Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009569

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter System Get Idle Time Command Detected"; flow:to_client,established; content:"stdapi_ui_get_idle_time"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009570; classtype:successful-user; sid:2009570; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009570
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter System Get Idle Time Command Detected"; flow:to_client,established; content:"stdapi_ui_get_idle_time"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009570; classtype:successful-user; sid:2009570; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter System Get Idle Time Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009570

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Make Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_mkdir"; depth:55; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009571; classtype:successful-user; sid:2009571; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009571
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Make Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_mkdir"; depth:55; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009571; classtype:successful-user; sid:2009571; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Make Directory Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009571

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Remove Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_delete_dir"; depth:57; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009572; classtype:successful-user; sid:2009572; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009572
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Remove Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_delete_dir"; depth:57; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009572; classtype:successful-user; sid:2009572; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Remove Directory Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009572

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Change Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_chdir"; depth:57; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009573; classtype:successful-user; sid:2009573; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009573
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Change Directory Command Detected"; flow:to_client,established; content:"stdapi_fs_chdir"; depth:57; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009573; classtype:successful-user; sid:2009573; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Change Directory Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009573

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter List (ls) Command Detected"; flow:to_client,established; content:"stdapi_fs_ls"; depth:52; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009574; classtype:successful-user; sid:2009574; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009574
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter List (ls) Command Detected"; flow:to_client,established; content:"stdapi_fs_ls"; depth:52; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009574; classtype:successful-user; sid:2009574; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter List (ls) Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009574

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter rev2self Command Detected"; flow:to_client,established; content:"stdapi_sys_config_rev2self"; depth:52; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009575; classtype:successful-user; sid:2009575; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009575
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter rev2self Command Detected"; flow:to_client,established; content:"stdapi_sys_config_rev2self"; depth:52; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009575; classtype:successful-user; sid:2009575; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter rev2self Command Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009575

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Enabling/Disabling of Keyboard Detected"; flow:to_client,established; content:"stdapi_ui_enable_keyboard"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009576; classtype:successful-user; sid:2009576; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009576
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Enabling/Disabling of Keyboard Detected"; flow:to_client,established; content:"stdapi_ui_enable_keyboard"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009576; classtype:successful-user; sid:2009576; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Enabling/Disabling of Keyboard Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009576

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Enabling/Disabling of Mouse Detected"; flow:to_client,established; content:"stdapi_ui_enable_mouse"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009577; classtype:successful-user; sid:2009577; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009577
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Enabling/Disabling of Mouse Detected"; flow:to_client,established; content:"stdapi_ui_enable_mouse"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009577; classtype:successful-user; sid:2009577; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Enabling/Disabling of Mouse Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009577

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File/Memory Interaction Detected"; flow:to_client,established; content:"stdapi_fs_file_expand_path"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009578; classtype:successful-user; sid:2009578; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009578
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File/Memory Interaction Detected"; flow:to_client,established; content:"stdapi_fs_file_expand_path"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009578; classtype:successful-user; sid:2009578; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter File/Memory Interaction Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009578

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Registry Interation Detected"; flow:to_client,established; content:"stdapi_registry_create_key"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009579; classtype:successful-user; sid:2009579; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009579
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Registry Interation Detected"; flow:to_client,established; content:"stdapi_registry_create_key"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009579; classtype:successful-user; sid:2009579; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Registry Interation Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009579

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File Upload Detected"; flow:to_client,established; content:"core_channel_write"; depth:50; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009580; classtype:successful-user; sid:2009580; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009580
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File Upload Detected"; flow:to_client,established; content:"core_channel_write"; depth:50; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009580; classtype:successful-user; sid:2009580; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter File Upload Detected** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009580

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Channel Interaction Detected, Likely Interaction With Executable"; flow:to_client,established; content:"core_channel_interact"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009651; classtype:successful-user; sid:2009651; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009651
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Channel Interaction Detected, Likely Interaction With Executable"; flow:to_client,established; content:"core_channel_interact"; depth:60; reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf; reference:url,doc.emergingthreats.net/2009651; classtype:successful-user; sid:2009651; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit Meterpreter Channel Interaction Detected, Likely Interaction With Executable** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-user

URL reference : url,www.nologin.org/Downloads/Papers/meterpreter.pdf|url,doc.emergingthreats.net/2009651

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET ATTACK_RESPONSE Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host"; flow:established; content:"|40 00 41 00 42 0043 00 44 00 6d 65 74 73 72 76 2e 64 6c 6c 00 49 6e 69 74 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61|"; reference:url,doc.emergingthreats.net/2010454; classtype:successful-admin; sid:2010454; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010454
`#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET ATTACK_RESPONSE Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host"; flow:established; content:"|40 00 41 00 42 0043 00 44 00 6d 65 74 73 72 76 2e 64 6c 6c 00 49 6e 69 74 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61|"; reference:url,doc.emergingthreats.net/2010454; classtype:successful-admin; sid:2010454; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-admin

URL reference : url,doc.emergingthreats.net/2010454

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE c99shell phpshell detected"; flow:established,from_server; content:"c99shell"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007652; classtype:web-application-activity; sid:2007652; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007652
`#alert tcp $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE c99shell phpshell detected"; flow:established,from_server; content:"c99shell"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007652; classtype:web-application-activity; sid:2007652; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **c99shell phpshell detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007652

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET 139 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Weak Netbios Lanman Auth Challenge Detected"; flow:from_server; content:"|ff 53 4d 42|"; content:"|00 11 22 33 44 55 66 77 88|"; reference:url,doc.emergingthreats.net/bin/view/Main/2006417; classtype:policy-violation; sid:2006417; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2006417
`alert tcp $HOME_NET 139 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Weak Netbios Lanman Auth Challenge Detected"; flow:from_server; content:"|ff 53 4d 42|"; content:"|00 11 22 33 44 55 66 77 88|"; reference:url,doc.emergingthreats.net/bin/view/Main/2006417; classtype:policy-violation; sid:2006417; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Weak Netbios Lanman Auth Challenge Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2006417

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"ET ATTACK_RESPONSE FTP CWD to windows system32 - Suspicious"; flow:established,to_server; content:"CWD C|3a|\\WINDOWS\\system32\\"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/bin/view/Main/2008556; classtype:trojan-activity; sid:2008556; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008556
`alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"ET ATTACK_RESPONSE FTP CWD to windows system32 - Suspicious"; flow:established,to_server; content:"CWD C|3a|\\WINDOWS\\system32\\"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/bin/view/Main/2008556; classtype:trojan-activity; sid:2008556; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **FTP CWD to windows system32 - Suspicious** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008556

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : HUNTING

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Outbound PHP Connection"; flow: established,to_server; content:"From|3a| anon@anon.com"; nocase; offset: 0; depth: 19; content:"User-Agent|3a| PHP"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001628; classtype:web-application-activity; sid:2001628; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001628
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Outbound PHP Connection"; flow: established,to_server; content:"From|3a| anon@anon.com"; nocase; offset: 0; depth: 19; content:"User-Agent|3a| PHP"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2001628; classtype:web-application-activity; sid:2001628; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Outbound PHP Connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001628

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET ATTACK_RESPONSE r57 phpshell source being uploaded"; flow:established,to_server; content:"/*  (c)oded by 1dt.w0lf"; content:"/*  RST/GHC http"; distance:0; reference:url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755; reference:url,doc.emergingthreats.net/bin/view/Main/2003536; classtype:web-application-activity; sid:2003536; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003536
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET ATTACK_RESPONSE r57 phpshell source being uploaded"; flow:established,to_server; content:"/*  (c)oded by 1dt.w0lf"; content:"/*  RST/GHC http"; distance:0; reference:url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755; reference:url,doc.emergingthreats.net/bin/view/Main/2003536; classtype:web-application-activity; sid:2003536; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **r57 phpshell source being uploaded** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755|url,doc.emergingthreats.net/bin/view/Main/2003536

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE RFI Scanner detected"; flow:established,from_server; content:"RFI Scanner"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007653; classtype:web-application-activity; sid:2007653; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007653
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE RFI Scanner detected"; flow:established,from_server; content:"RFI Scanner"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007653; classtype:web-application-activity; sid:2007653; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **RFI Scanner detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007653

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE C99 Modified phpshell detected"; flow:established,from_server; content:"C99 Modified"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007654; classtype:web-application-activity; sid:2007654; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007654
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE C99 Modified phpshell detected"; flow:established,from_server; content:"C99 Modified"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007654; classtype:web-application-activity; sid:2007654; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **C99 Modified phpshell detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007654

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE lila.jpg phpshell detected"; flow:established,from_server; content:"CMD PHP"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007655; classtype:web-application-activity; sid:2007655; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007655
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE lila.jpg phpshell detected"; flow:established,from_server; content:"CMD PHP"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007655; classtype:web-application-activity; sid:2007655; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **lila.jpg phpshell detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007655

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE ALBANIA id.php detected"; flow:established,from_server; content:"UNITED ALBANIANS aka ALBOSS PARADISE"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007656; classtype:web-application-activity; sid:2007656; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007656
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE ALBANIA id.php detected"; flow:established,from_server; content:"UNITED ALBANIANS aka ALBOSS PARADISE"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007656; classtype:web-application-activity; sid:2007656; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ALBANIA id.php detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007656

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Mic22 id.php detected"; flow:established,from_server; content:"Mic22"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007657; classtype:web-application-activity; sid:2007657; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007657
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Mic22 id.php detected"; flow:established,from_server; content:"Mic22"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007657; classtype:web-application-activity; sid:2007657; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Mic22 id.php detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007657

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - user"; flow:established,from_server; dsize:>7; content:"USER "; depth:5; offset:0; content:" |0d 0a|"; distance:1; flowbits:set,ET.strippedftpuser; reference:url,doc.emergingthreats.net/bin/view/Main/2007715; classtype:trojan-activity; sid:2007715; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007715
`#alert tcp $HOME_NET 1024: -> any 1024: (msg:"ET ATTACK_RESPONSE Off-Port FTP Without Banners - user"; flow:established,from_server; dsize:>7; content:"USER "; depth:5; offset:0; content:" |0d 0a|"; distance:1; flowbits:set,ET.strippedftpuser; reference:url,doc.emergingthreats.net/bin/view/Main/2007715; classtype:trojan-activity; sid:2007715; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Off-Port FTP Without Banners - user** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007715

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 1024: -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner on High Port (WinFtpd)"; flow:established,from_server; dsize:<18; content:"220 WinFtpd"; depth:11; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2007725; classtype:trojan-activity; sid:2007725; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007725
`alert tcp any 1024: -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner on High Port (WinFtpd)"; flow:established,from_server; dsize:<18; content:"220 WinFtpd"; depth:11; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2007725; classtype:trojan-activity; sid:2007725; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner on High Port (WinFtpd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007725

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 1024: -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner on High Port (StnyFtpd)"; flow:established,from_server; dsize:<30; content:"220 StnyFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2007726; classtype:trojan-activity; sid:2007726; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007726
`alert tcp any 1024: -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner on High Port (StnyFtpd)"; flow:established,from_server; dsize:<30; content:"220 StnyFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2007726; classtype:trojan-activity; sid:2007726; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner on High Port (StnyFtpd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2007726

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET ATTACK_RESPONSE Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host"; flow:established; content:"metsrv.dll|00|MZ"; fast_pattern; depth:13; content:"!This program cannot be run in DOS mode."; distance:75; within:40; reference:url,doc.emergingthreats.net/2009581; classtype:successful-admin; sid:2009581; rev:4; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009581
`#alert tcp $EXTERNAL_NET 1024:65535 -> $HOME_NET 1024:65535 (msg:"ET ATTACK_RESPONSE Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host"; flow:established; content:"metsrv.dll|00|MZ"; fast_pattern; depth:13; content:"!This program cannot be run in DOS mode."; distance:75; within:40; reference:url,doc.emergingthreats.net/2009581; classtype:successful-admin; sid:2009581; rev:4; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Metasploit/Meterpreter - Sending metsrv.dll to Compromised Host** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : successful-admin

URL reference : url,doc.emergingthreats.net/2009581

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (warFTPd)"; flow:established,from_server; content:"220 "; content:"--warFTPd "; depth:40; nocase; reference:url,www.warftp.org; reference:url,doc.emergingthreats.net/bin/view/Main/2003464; classtype:trojan-activity; sid:2003464; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003464
`alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (warFTPd)"; flow:established,from_server; content:"220 "; content:"--warFTPd "; depth:40; nocase; reference:url,www.warftp.org; reference:url,doc.emergingthreats.net/bin/view/Main/2003464; classtype:trojan-activity; sid:2003464; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner (warFTPd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.warftp.org|url,doc.emergingthreats.net/bin/view/Main/2003464

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (freeFTPd)"; flow:established,from_server; content:"220 "; content:"--freeFTPd "; depth:40; nocase; reference:url,www.freeftp.com; reference:url,doc.emergingthreats.net/bin/view/Main/2003465; classtype:trojan-activity; sid:2003465; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003465
`alert tcp any 21 -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Unusual FTP Server Banner (freeFTPd)"; flow:established,from_server; content:"220 "; content:"--freeFTPd "; depth:40; nocase; reference:url,www.freeftp.com; reference:url,doc.emergingthreats.net/bin/view/Main/2003465; classtype:trojan-activity; sid:2003465; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Unusual FTP Server Banner (freeFTPd)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.freeftp.com|url,doc.emergingthreats.net/bin/view/Main/2003465

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ipconfig Response Detected"; flow:from_server,established; content:"Windows IP Configuration"; content:"Ethernet adapter Local Area Connection"; offset:35; depth:55; reference:url,en.wikipedia.org/wiki/Ipconfig; reference:url,doc.emergingthreats.net/2009676; classtype:successful-recon-limited; sid:2009676; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009676
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ipconfig Response Detected"; flow:from_server,established; content:"Windows IP Configuration"; content:"Ethernet adapter Local Area Connection"; offset:35; depth:55; reference:url,en.wikipedia.org/wiki/Ipconfig; reference:url,doc.emergingthreats.net/2009676; classtype:successful-recon-limited; sid:2009676; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Ipconfig Response Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,en.wikipedia.org/wiki/Ipconfig|url,doc.emergingthreats.net/2009676

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system"; flow:established; dsize:<110; content:"Microsoft Windows "; depth:20; content:"Copyright 1985-20"; distance:0; content:"Microsoft Corp"; distance:0; content:"|0a 0a|"; distance:0; reference:url,doc.emergingthreats.net/bin/view/Main/2008953; classtype:successful-admin; sid:2008953; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008953
`alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system"; flow:established; dsize:<110; content:"Microsoft Windows "; depth:20; content:"Copyright 1985-20"; distance:0; content:"Microsoft Corp"; distance:0; content:"|0a 0a|"; distance:0; reference:url,doc.emergingthreats.net/bin/view/Main/2008953; classtype:successful-admin; sid:2008953; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible MS CMD Shell opened on local system** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008953

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Windows 7 CMD Shell from Local System"; flow:established; dsize:<160; content:"Microsoft Windows [Version "; depth:30; content:"Copyright (c)"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2012690; rev:1; metadata:created_at 2011_04_17, updated_at 2011_04_17;)

# 2012690
`alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Windows 7 CMD Shell from Local System"; flow:established; dsize:<160; content:"Microsoft Windows [Version "; depth:30; content:"Copyright (c)"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2012690; rev:1; metadata:created_at 2011_04_17, updated_at 2011_04_17;)
` 

Name : **Windows 7 CMD Shell from Local System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-17

Last modified date : 2011-04-17

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned userid"; content:"uid="; byte_test:5,<,65537,0,relative,string; content:" gid="; within:15; byte_test:5,<,65537,0,relative,string; classtype:bad-unknown; sid:2101882; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101882
`#alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned userid"; content:"uid="; byte_test:5,<,65537,0,relative,string; content:" gid="; within:15; byte_test:5,<,65537,0,relative,string; classtype:bad-unknown; sid:2101882; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned userid** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 11

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned nobody"; flow:from_server,established; content:"uid="; content:"|28|nobody|29|"; classtype:bad-unknown; sid:2101883; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101883
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned nobody"; flow:from_server,established; content:"uid="; content:"|28|nobody|29|"; classtype:bad-unknown; sid:2101883; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned nobody** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned http"; flow:from_server,established; content:"uid="; content:"|28|http|29|"; classtype:bad-unknown; sid:2101885; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101885
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned http"; flow:from_server,established; content:"uid="; content:"|28|http|29|"; classtype:bad-unknown; sid:2101885; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned http** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned apache"; flow:from_server,established; content:"uid="; content:"|28|apache|29|"; classtype:bad-unknown; sid:2101886; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101886
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned apache"; flow:from_server,established; content:"uid="; content:"|28|apache|29|"; classtype:bad-unknown; sid:2101886; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned apache** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE index of /cgi-bin/ response"; flow:from_server,established; content:"Index of /cgi-bin/"; nocase; reference:nessus,10039; classtype:bad-unknown; sid:2101666; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101666
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE index of /cgi-bin/ response"; flow:from_server,established; content:"Index of /cgi-bin/"; nocase; reference:nessus,10039; classtype:bad-unknown; sid:2101666; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **index of /cgi-bin/ response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : nessus,10039

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE Invalid URL"; flow:from_server,established; content:"Invalid URL"; nocase; reference:url,www.microsoft.com/technet/security/bulletin/MS00-063.mspx; classtype:attempted-recon; sid:2101200; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101200
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE Invalid URL"; flow:from_server,established; content:"Invalid URL"; nocase; reference:url,www.microsoft.com/technet/security/bulletin/MS00-063.mspx; classtype:attempted-recon; sid:2101200; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Invalid URL** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,www.microsoft.com/technet/security/bulletin/MS00-063.mspx

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE command completed"; flow:established; content:"Command completed"; nocase; reference:bugtraq,1806; classtype:bad-unknown; sid:2100494; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100494
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE command completed"; flow:established; content:"Command completed"; nocase; reference:bugtraq,1806; classtype:bad-unknown; sid:2100494; rev:12; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **command completed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,1806

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 12

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE command error"; flow:established; content:"Bad command or filename"; nocase; classtype:bad-unknown; sid:2100495; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100495
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE command error"; flow:established; content:"Bad command or filename"; nocase; classtype:bad-unknown; sid:2100495; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **command error** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE file copied ok"; flow:established; content:"1 file|28|s|29| copied"; nocase; reference:bugtraq,1806; reference:cve,2000-0884; classtype:bad-unknown; sid:2100497; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100497
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE file copied ok"; flow:established; content:"1 file|28|s|29| copied"; nocase; reference:bugtraq,1806; reference:cve,2000-0884; classtype:bad-unknown; sid:2100497; rev:14; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **file copied ok** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : bugtraq,1806|cve,2000-0884

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 14

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET 500 -> $EXTERNAL_NET 500 (msg:"GPL ATTACK_RESPONSE isakmp login failed"; content:"|10 05|"; depth:2; offset:17; content:"|00 00 00 01 01 00 00 18|"; within:8; distance:13; classtype:misc-activity; sid:2102043; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102043
`alert udp $HOME_NET 500 -> $EXTERNAL_NET 500 (msg:"GPL ATTACK_RESPONSE isakmp login failed"; content:"|10 05|"; depth:2; offset:17; content:"|00 00 00 01 01 00 00 18|"; within:8; distance:13; classtype:misc-activity; sid:2102043; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **isakmp login failed** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL ATTACK_RESPONSE del attempt"; flow:to_server,established; content:"&del+/s+c|3A 5C|*.*"; nocase; classtype:web-application-attack; sid:2101008; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101008
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL ATTACK_RESPONSE del attempt"; flow:to_server,established; content:"&del+/s+c|3A 5C|*.*"; nocase; classtype:web-application-attack; sid:2101008; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **del attempt** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE directory listing"; flow:established; content:"Volume Serial Number"; classtype:bad-unknown; sid:2101292; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101292
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE directory listing"; flow:established; content:"Volume Serial Number"; classtype:bad-unknown; sid:2101292; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **directory listing** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100498
`alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned root** 

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

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned web"; flow:from_server,established; content:"uid="; content:"|28|web|29|"; within:25; classtype:bad-unknown; sid:2101884; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101884
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"GPL ATTACK_RESPONSE id check returned web"; flow:from_server,established; content:"uid="; content:"|28|web|29|"; within:25; classtype:bad-unknown; sid:2101884; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **id check returned web** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE HTTP 401 Unauthorized"; flow:from_server,established; content:"401"; http_stat_code; threshold: type both, count 1, seconds 300, track by_dst; reference:url,doc.emergingthreats.net/2009345; classtype:attempted-recon; sid:2009345; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009345
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE HTTP 401 Unauthorized"; flow:from_server,established; content:"401"; http_stat_code; threshold: type both, count 1, seconds 300, track by_dst; reference:url,doc.emergingthreats.net/2009345; classtype:attempted-recon; sid:2009345; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **HTTP 401 Unauthorized** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009345

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Frequent HTTP 401 Unauthorized - Possible Brute Force Attack"; flow:from_server,established; content:"401"; http_stat_code; threshold:type both, track by_dst, count 30, seconds 60; reference:url,doc.emergingthreats.net/2009346; classtype:attempted-recon; sid:2009346; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009346
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Frequent HTTP 401 Unauthorized - Possible Brute Force Attack"; flow:from_server,established; content:"401"; http_stat_code; threshold:type both, track by_dst, count 30, seconds 60; reference:url,doc.emergingthreats.net/2009346; classtype:attempted-recon; sid:2009346; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Frequent HTTP 401 Unauthorized - Possible Brute Force Attack** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : url,doc.emergingthreats.net/2009346

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Backdoor reDuh http initiate"; flow:to_server,established; content:"?action=checkPort&port="; http_uri; content:"Java/"; http_user_agent; reference:url,www.sensepost.com/labs/tools/pentest/reduh; reference:url,doc.emergingthreats.net/2011667; classtype:trojan-activity; sid:2011667; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011667
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Backdoor reDuh http initiate"; flow:to_server,established; content:"?action=checkPort&port="; http_uri; content:"Java/"; http_user_agent; reference:url,www.sensepost.com/labs/tools/pentest/reduh; reference:url,doc.emergingthreats.net/2011667; classtype:trojan-activity; sid:2011667; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Backdoor reDuh http initiate** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sensepost.com/labs/tools/pentest/reduh|url,doc.emergingthreats.net/2011667

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Backdoor reDuh http tunnel"; flow:to_server,established; content:"?action=getData&servicePort="; http_uri; content:"Java/"; http_user_agent; threshold:type limit, track by_src, count 1, seconds 300; reference:url,www.sensepost.com/labs/tools/pentest/reduh; reference:url,doc.emergingthreats.net/2011668; classtype:trojan-activity; sid:2011668; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011668
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Backdoor reDuh http tunnel"; flow:to_server,established; content:"?action=getData&servicePort="; http_uri; content:"Java/"; http_user_agent; threshold:type limit, track by_src, count 1, seconds 300; reference:url,www.sensepost.com/labs/tools/pentest/reduh; reference:url,doc.emergingthreats.net/2011668; classtype:trojan-activity; sid:2011668; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Backdoor reDuh http tunnel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.sensepost.com/labs/tools/pentest/reduh|url,doc.emergingthreats.net/2011668

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible Ipconfig Information Detected in HTTP Response"; flow:from_server,established; file_data; content:"Windows IP Configuration"; content:"Ethernet adapter Local Area Connection"; distance:8; within:40; reference:url,en.wikipedia.org/wiki/Ipconfig; reference:url,doc.emergingthreats.net/2009675; classtype:successful-recon-limited; sid:2009675; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009675
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible Ipconfig Information Detected in HTTP Response"; flow:from_server,established; file_data; content:"Windows IP Configuration"; content:"Ethernet adapter Local Area Connection"; distance:8; within:40; reference:url,en.wikipedia.org/wiki/Ipconfig; reference:url,doc.emergingthreats.net/2009675; classtype:successful-recon-limited; sid:2009675; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible Ipconfig Information Detected in HTTP Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,en.wikipedia.org/wiki/Ipconfig|url,doc.emergingthreats.net/2009675

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any any (msg:"ET ATTACK_RESPONSE Net User Command Response"; flow:established; content:"User accounts for |5C 5C|"; fast_pattern; content:"-------------------------------------------------------------------------------"; distance:0; classtype:successful-user; sid:2017025; rev:3; metadata:created_at 2013_06_17, updated_at 2013_06_17;)

# 2017025
`alert tcp any any -> any any (msg:"ET ATTACK_RESPONSE Net User Command Response"; flow:established; content:"User accounts for |5C 5C|"; fast_pattern; content:"-------------------------------------------------------------------------------"; distance:0; classtype:successful-user; sid:2017025; rev:3; metadata:created_at 2013_06_17, updated_at 2013_06_17;)
` 

Name : **Net User Command Response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-06-17

Last modified date : 2013-06-17

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Non-Local Burp Proxy Error"; flow:established,to_client; content:"502"; http_stat_code; content:"Bad gateway"; http_stat_msg; file_data; content:"Burp proxy error|3A 20|"; within:18; reference:url,portswigger.net/burp/proxy.html; classtype:successful-admin; sid:2017148; rev:3; metadata:created_at 2013_07_15, updated_at 2013_07_15;)

# 2017148
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Non-Local Burp Proxy Error"; flow:established,to_client; content:"502"; http_stat_code; content:"Bad gateway"; http_stat_msg; file_data; content:"Burp proxy error|3A 20|"; within:18; reference:url,portswigger.net/burp/proxy.html; classtype:successful-admin; sid:2017148; rev:3; metadata:created_at 2013_07_15, updated_at 2013_07_15;)
` 

Name : **Non-Local Burp Proxy Error** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,portswigger.net/burp/proxy.html

CVE reference : Not defined

Creation date : 2013-07-15

Last modified date : 2013-07-15

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE python shell spawn attempt"; flow:established,to_client; content:"pty|2e|spawn|2822|/bin/sh|2229|"; depth:64; classtype:trojan-activity; sid:2017317; rev:2; metadata:created_at 2013_08_12, updated_at 2013_08_12;)

# 2017317
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE python shell spawn attempt"; flow:established,to_client; content:"pty|2e|spawn|2822|/bin/sh|2229|"; depth:64; classtype:trojan-activity; sid:2017317; rev:2; metadata:created_at 2013_08_12, updated_at 2013_08_12;)
` 

Name : **python shell spawn attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-08-12

Last modified date : 2013-08-12

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Possible  MS CMD Shell opened on local system 2"; dsize:<200; content:"Microsoft Windows "; depth:40; content:"[Version"; distance:0; within:10; content:"Copyright (c) 2009"; distance:0; content:"Microsoft Corp"; distance:0; reference:url,doc.emergingthreats.net/bin/view/Main/2008953; classtype:successful-admin; sid:2018392; rev:1; metadata:created_at 2014_04_15, updated_at 2014_04_15;)

# 2018392
`alert tcp $HOME_NET any -> any any (msg:"ET ATTACK_RESPONSE Possible  MS CMD Shell opened on local system 2"; dsize:<200; content:"Microsoft Windows "; depth:40; content:"[Version"; distance:0; within:10; content:"Copyright (c) 2009"; distance:0; content:"Microsoft Corp"; distance:0; reference:url,doc.emergingthreats.net/bin/view/Main/2008953; classtype:successful-admin; sid:2018392; rev:1; metadata:created_at 2014_04_15, updated_at 2014_04_15;)
` 

Name : **Possible  MS CMD Shell opened on local system 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008953

CVE reference : Not defined

Creation date : 2014-04-15

Last modified date : 2014-04-15

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Output of id command from HTTP server"; flow:established; content:"uid="; pcre:"/^\d+[^\r\n\s]+/R"; content:" gid="; within:5; pcre:"/^\d+[^\r\n\s]+/R"; content:" groups="; within:8; classtype:bad-unknown; sid:2019284; rev:3; metadata:created_at 2014_09_26, updated_at 2014_09_26;)

# 2019284
`alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Output of id command from HTTP server"; flow:established; content:"uid="; pcre:"/^\d+[^\r\n\s]+/R"; content:" gid="; within:5; pcre:"/^\d+[^\r\n\s]+/R"; content:" groups="; within:8; classtype:bad-unknown; sid:2019284; rev:3; metadata:created_at 2014_09_26, updated_at 2014_09_26;)
` 

Name : **Output of id command from HTTP server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2014-09-26

Last modified date : 2014-09-26

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $HOME_NET 623 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible IPMI 2.0 RAKP Remote SHA1 Password Hash Retreival RAKP message 2 status code Unauthorized Name"; content:"|06 13|"; offset:4; depth:2; content:"|0d|"; distance:11; within:1; classtype:protocol-command-decode; sid:2017121; rev:2; metadata:created_at 2013_07_09, updated_at 2013_07_09;)

# 2017121
`alert udp $HOME_NET 623 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible IPMI 2.0 RAKP Remote SHA1 Password Hash Retreival RAKP message 2 status code Unauthorized Name"; content:"|06 13|"; offset:4; depth:2; content:"|0d|"; distance:11; within:1; classtype:protocol-command-decode; sid:2017121; rev:2; metadata:created_at 2013_07_09, updated_at 2013_07_09;)
` 

Name : **Possible IPMI 2.0 RAKP Remote SHA1 Password Hash Retreival RAKP message 2 status code Unauthorized Name** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-09

Last modified date : 2013-07-09

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Powershell Banner Outbound"; flow:established; content:"Windows PowerShell"; content:"Copyright |28|C|29| 20"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2020084; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)

# 2020084
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Powershell Banner Outbound"; flow:established; content:"Windows PowerShell"; content:"Copyright |28|C|29| 20"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2020084; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)
` 

Name : **Microsoft Powershell Banner Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-05

Last modified date : 2015-01-05

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft CScript Banner Outbound"; flow:established; content:"Windows Script Host Version"; content:"Copyright |28|C|29|"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2020085; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)

# 2020085
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft CScript Banner Outbound"; flow:established; content:"Windows Script Host Version"; content:"Copyright |28|C|29|"; distance:0; content:"Microsoft Corp"; distance:0; classtype:successful-admin; sid:2020085; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)
` 

Name : **Microsoft CScript Banner Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-05

Last modified date : 2015-01-05

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft WMIC Prompt Outbound"; flow:established; content:"wmic|3a|root|5c|cli>"; classtype:successful-admin; sid:2020086; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)

# 2020086
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft WMIC Prompt Outbound"; flow:established; content:"wmic|3a|root|5c|cli>"; classtype:successful-admin; sid:2020086; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)
` 

Name : **Microsoft WMIC Prompt Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-05

Last modified date : 2015-01-05

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Netsh Firewall Disable Output Outbound"; flow:established; content:"netsh firewall|22| is deprecated|3b|"; content:"use |22|netsh advfirewall"; distance:0; content:"Ok."; distance:0; classtype:successful-admin; sid:2020087; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)

# 2020087
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Netsh Firewall Disable Output Outbound"; flow:established; content:"netsh firewall|22| is deprecated|3b|"; content:"use |22|netsh advfirewall"; distance:0; content:"Ok."; distance:0; classtype:successful-admin; sid:2020087; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)
` 

Name : **Microsoft Netsh Firewall Disable Output Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-05

Last modified date : 2015-01-05

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SysInternals sc.exe Output Outbound"; flow:established; content:"SERVICE_NAME|3a|"; content:"TYPE"; distance:0; content:"SERVICE_EXIT_CODE"; distance:0; classtype:successful-admin; sid:2020088; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)

# 2020088
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SysInternals sc.exe Output Outbound"; flow:established; content:"SERVICE_NAME|3a|"; content:"TYPE"; distance:0; content:"SERVICE_EXIT_CODE"; distance:0; classtype:successful-admin; sid:2020088; rev:1; metadata:created_at 2015_01_05, updated_at 2015_01_05;)
` 

Name : **SysInternals sc.exe Output Outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-admin

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-01-05

Last modified date : 2015-01-05

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"mysql_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020507; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020507
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"mysql_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020507; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQL syntax"; fast_pattern; content:"MySQL"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020506; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020506
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQL syntax"; fast_pattern; content:"MySQL"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020506; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"MySqlException (0x"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020508; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020508
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"MySqlException (0x"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020508; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"valid MySQL result"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020509; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020509
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"valid MySQL result"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020509; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"MySqlClient."; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020510; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020510
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"MySqlClient."; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020510; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"com.mysql.jdbc.exceptions"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020511; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020511
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"com.mysql.jdbc.exceptions"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020511; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **MySQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 4

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"PostgreSQL"; fast_pattern; content:"ERROR"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020512; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020512
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"PostgreSQL"; fast_pattern; content:"ERROR"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020512; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"Wpg_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020513; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020513
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"Wpg_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020513; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"valid PostgreSQL result"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020514; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020514
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"valid PostgreSQL result"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020514; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Npgsql."; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020515; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020515
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Npgsql."; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020515; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"org.postgresql.util.PSQLException"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020516; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020516
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"org.postgresql.util.PSQLException"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020516; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"ERROR|3a 20 20|syntax error at or near"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020517; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020517
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE PostgreSQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"ERROR|3a 20 20|syntax error at or near"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020517; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **PostgreSQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Driver"; fast_pattern; pcre:"/^ SQL[-_ ]Server/R"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020518; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020518
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Driver"; fast_pattern; pcre:"/^ SQL[-_ ]Server/R"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020518; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"OLEDB"; fast_pattern; content:"|20|SQL Server"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020519; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020519
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"OLEDB"; fast_pattern; content:"|20|SQL Server"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020519; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"mssql_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020521; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020521
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"mssql_"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020521; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; fast_pattern; content:"System.Data.SqlClient."; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020523; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020523
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; fast_pattern; content:"System.Data.SqlClient."; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020523; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; fast_pattern; content:"Roadhouse.Cms"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020524; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020524
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; fast_pattern; content:"Roadhouse.Cms"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020524; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Microsoft Access"; fast_pattern; pcre:"/^ \d+ Driver/R"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020525; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020525
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Microsoft Access"; fast_pattern; pcre:"/^ \d+ Driver/R"; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020525; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft Access error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"JET Database Engine"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020526; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020526
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"JET Database Engine"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020526; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft Access error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Access Database Engine"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020527; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020527
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft Access error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Access Database Engine"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020527; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft Access error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"ORA-"; fast_pattern:only; pcre:"/ORA-\d{4}/"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020528; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020528
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"ORA-"; fast_pattern:only; pcre:"/ORA-\d{4}/"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020528; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Oracle error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Oracle error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020529; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020529
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Oracle error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020529; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Oracle error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Oracle"; fast_pattern; content:"Driver"; distance:0; within:12; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020530; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020530
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Oracle"; fast_pattern; content:"Driver"; distance:0; within:12; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020530; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Oracle error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"oci_"; distance:0; fast_pattern; pcre:"/Warning.*\Woci_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020531; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020531
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"oci_"; distance:0; fast_pattern; pcre:"/Warning.*\Woci_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020531; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Oracle error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"ora_"; fast_pattern; distance:0; pcre:"/Warning.*\Wora_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020532; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020532
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Oracle error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"ora_"; fast_pattern; distance:0; pcre:"/Warning.*\Wora_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020532; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Oracle error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"CLI Driver"; fast_pattern:only; pcre:"/CLI Driver.*DB2/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020533; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020533
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"CLI Driver"; fast_pattern:only; pcre:"/CLI Driver.*DB2/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020533; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **DB2 error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"DB2 SQL error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020534; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020534
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"DB2 SQL error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020534; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **DB2 error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"bdb2_"; fast_pattern:only; pcre:"/bdb2_\w+\(/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020535; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020535
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE DB2 error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"bdb2_"; fast_pattern:only; pcre:"/bdb2_\w+\(/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020535; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **DB2 error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Informix error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; content:"Informix"; fast_pattern; pcre:"/Exception.*Informix/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020536; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020536
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Informix error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception"; content:"Informix"; fast_pattern; pcre:"/Exception.*Informix/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020536; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Informix error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Firebird error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Dynamic SQL Error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020537; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020537
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Firebird error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Dynamic SQL Error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020537; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Firebird error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Firebird error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Dynamic SQL Error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020538; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020538
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Firebird error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Dynamic SQL Error"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020538; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Firebird error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQLite/JDBCDriver"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020539; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020539
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQLite/JDBCDriver"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020539; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQLite.Exception"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020540; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020540
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQLite.Exception"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020540; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"System.Data.SQLite.SQLiteException"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020541; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020541
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"System.Data.SQLite.SQLiteException"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020541; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"SQLite3|3a 3a|"; fast_pattern; distance:0; pcre:"/Warning.*SQLite3::/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020543; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020543
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"SQLite3|3a 3a|"; fast_pattern; distance:0; pcre:"/Warning.*SQLite3::/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020543; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"[SQLITE_ERROR]"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020544; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020544
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"[SQLITE_ERROR]"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020544; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SAP MaxDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQL error"; fast_pattern; content:"POS("; distance:0; pcre:"/SQL error.*POS\([0-9]+\)/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020545; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020545
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SAP MaxDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"SQL error"; fast_pattern; content:"POS("; distance:0; pcre:"/SQL error.*POS\([0-9]+\)/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020545; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SAP MaxDB error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SAP MaxDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"maxdb"; fast_pattern; distance:0; pcre:"/Warning.*maxdb/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020546; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020546
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SAP MaxDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"maxdb"; fast_pattern; distance:0; pcre:"/Warning.*maxdb/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020546; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SAP MaxDB error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"sybase"; fast_pattern; distance:0; pcre:"/i?Warning.*sybase/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020547; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020547
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"sybase"; fast_pattern; distance:0; pcre:"/i?Warning.*sybase/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020547; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Sybase error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Sybase message"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020548; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020548
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Sybase message"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020548; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Sybase error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Sybase Server message"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020549; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020549
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Sybase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Sybase Server message"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020549; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Sybase error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"ingres_"; fast_pattern; distance:0; pcre:"/Warning.*ingres_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020550; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020550
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"ingres_"; fast_pattern; distance:0; pcre:"/Warning.*ingres_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020550; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Ingres error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"sqlite_"; fast_pattern; distance:0; pcre:"/Warning.*sqlite_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020542; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020542
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE SQLite error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Warning"; content:"sqlite_"; fast_pattern; distance:0; pcre:"/Warning.*sqlite_/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020542; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **SQLite error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Ingres SQLSTATE"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020551; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020551
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Ingres SQLSTATE"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020551; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Ingres error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Ingres"; fast_pattern; content:"Driver"; distance:0; pcre:"/Ingres\W.*Driver/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020552; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020552
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Ingres error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Ingres"; fast_pattern; content:"Driver"; distance:0; pcre:"/Ingres\W.*Driver/m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020552; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Ingres error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Frontbase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception (condition )"; content:". Transaction rollback."; fast_pattern; distance:0; pcre:"/Exception (condition )\d+\. Transaction rollback\./m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020553; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020553
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Frontbase error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"Exception (condition )"; content:". Transaction rollback."; fast_pattern; distance:0; pcre:"/Exception (condition )\d+\. Transaction rollback\./m"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020553; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Frontbase error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE HSQLDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"org.hsqldb.jdbc"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020554; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020554
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE HSQLDB error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"org.hsqldb.jdbc"; fast_pattern:only; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020554; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **HSQLDB error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; content:"500 Internal Server Error"; file_data; content:"OLE DB Provider for SQL Server"; fast_pattern:only; pcre:"/SQL Server.*?error \x27[0-9a-f]{8}/mi"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020522; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020522
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; content:"500 Internal Server Error"; file_data; content:"OLE DB Provider for SQL Server"; fast_pattern:only; pcre:"/SQL Server.*?error \x27[0-9a-f]{8}/mi"; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020522; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"[Microsoft]"; content:"[ODBC SQL Server Driver]"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020520; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)

# 2020520
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Microsoft SQL error in HTTP response, possible SQL injection point"; flow:from_server,established; file_data; content:"[Microsoft]"; content:"[ODBC SQL Server Driver]"; fast_pattern; distance:0; threshold:type both,track by_src,count 1,seconds 60; classtype:web-application-attack; sid:2020520; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2015_02_24, updated_at 2016_07_01;)
` 

Name : **Microsoft SQL error in HTTP response, possible SQL injection point** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-02-24

Last modified date : 2016-07-01

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style)"; flow:established,from_server; file_data; content:"root|3a|x|3a|0|3a|0|3a|root|3a|/root|3a|/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002034; classtype:successful-recon-limited; sid:2002034; rev:12; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002034
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style)"; flow:established,from_server; file_data; content:"root|3a|x|3a|0|3a|0|3a|root|3a|/root|3a|/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2002034; classtype:successful-recon-limited; sid:2002034; rev:12; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible /etc/passwd via HTTP (linux style)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002034

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 12

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via SMTP (linux style)"; flow:established,to_server; content:"root|3a|x|3a|0|3a|0|3a|root|3a|/root|3a|/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003149; classtype:successful-recon-limited; sid:2003149; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003149
`alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via SMTP (linux style)"; flow:established,to_server; content:"root|3a|x|3a|0|3a|0|3a|root|3a|/root|3a|/"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003149; classtype:successful-recon-limited; sid:2003149; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible /etc/passwd via SMTP (linux style)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003149

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via SMTP (BSD style)"; flow:established,to_server; content:"root|3a|*|3a|0|3a|0|3a|"; nocase; content:"|3a|/root|3a|/bin"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003150; classtype:successful-recon-limited; sid:2003150; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003150
`alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via SMTP (BSD style)"; flow:established,to_server; content:"root|3a|*|3a|0|3a|0|3a|"; nocase; content:"|3a|/root|3a|/bin"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003150; classtype:successful-recon-limited; sid:2003150; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible /etc/passwd via SMTP (BSD style)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003150

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET 500 (msg:"ET ATTACK_RESPONSE Possible CVE-2016-1287 Inbound Reverse CLI Shellcode"; flow:to_server; content:"|ff ff ff|tcp/CONNECT/3/"; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}\/\d+\x00$/Ri"; reference:url,raw.githubusercontent.com/exodusintel/disclosures/master/CVE_2016_1287_PoC; classtype:attempted-admin; sid:2022819; rev:1; metadata:created_at 2016_05_18, updated_at 2016_05_18;)

# 2022819
`alert udp $EXTERNAL_NET any -> $HOME_NET 500 (msg:"ET ATTACK_RESPONSE Possible CVE-2016-1287 Inbound Reverse CLI Shellcode"; flow:to_server; content:"|ff ff ff|tcp/CONNECT/3/"; pcre:"/^(?:\d{1,3}\.){3}\d{1,3}\/\d+\x00$/Ri"; reference:url,raw.githubusercontent.com/exodusintel/disclosures/master/CVE_2016_1287_PoC; classtype:attempted-admin; sid:2022819; rev:1; metadata:created_at 2016_05_18, updated_at 2016_05_18;)
` 

Name : **Possible CVE-2016-1287 Inbound Reverse CLI Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,raw.githubusercontent.com/exodusintel/disclosures/master/CVE_2016_1287_PoC

CVE reference : Not defined

Creation date : 2016-05-18

Last modified date : 2016-05-18

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE 401TRG Perl DDoS IRCBot File Download"; flow:established,from_server; content:"|6d 79 20 24 70 72 6f 63 65 73 73 20 3d 20 24 72 70 73 5b 72 61 6e 64 20 73 63 61 6c 61 72 20 40 72 70 73 5d 3b|"; metadata: former_category ATTACK_RESPONSE; classtype:trojan-activity; sid:2024977; rev:2; metadata:affected_product Apache_HTTP_server, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2017_11_07, malware_family webshell, performance_impact Moderate, updated_at 2017_11_07;)

# 2024977
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE 401TRG Perl DDoS IRCBot File Download"; flow:established,from_server; content:"|6d 79 20 24 70 72 6f 63 65 73 73 20 3d 20 24 72 70 73 5b 72 61 6e 64 20 73 63 61 6c 61 72 20 40 72 70 73 5d 3b|"; metadata: former_category ATTACK_RESPONSE; classtype:trojan-activity; sid:2024977; rev:2; metadata:affected_product Apache_HTTP_server, attack_target Web_Server, deployment Datacenter, signature_severity Major, created_at 2017_11_07, malware_family webshell, performance_impact Moderate, updated_at 2017_11_07;)
` 

Name : **401TRG Perl DDoS IRCBot File Download** 

Attack target : Web_Server

Description : Alerts on successful wget of malicious perl script

Tags : Not defined

Affected products : Apache_HTTP_server

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-11-07

Last modified date : 2017-11-07

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : webshell

Type : SID

Performance Impact : Moderate



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE webr00t WebShell Access"; flow:established,to_server; content:"/?webr00t="; http_uri; metadata: former_category CURRENT_EVENTS; reference:url,blog.sucuri.net/2013/11/case-study-analyzing-a-wordpress-attack-dissecting-the-webr00t-cgi-shell-part-i.html; classtype:trojan-activity; sid:2017701; rev:4; metadata:created_at 2013_11_08, updated_at 2017_11_28;)

# 2017701
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE webr00t WebShell Access"; flow:established,to_server; content:"/?webr00t="; http_uri; metadata: former_category CURRENT_EVENTS; reference:url,blog.sucuri.net/2013/11/case-study-analyzing-a-wordpress-attack-dissecting-the-webr00t-cgi-shell-part-i.html; classtype:trojan-activity; sid:2017701; rev:4; metadata:created_at 2013_11_08, updated_at 2017_11_28;)
` 

Name : **webr00t WebShell Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,blog.sucuri.net/2013/11/case-study-analyzing-a-wordpress-attack-dissecting-the-webr00t-cgi-shell-part-i.html

CVE reference : Not defined

Creation date : 2013-11-08

Last modified date : 2017-11-28

Rev version : 4

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE PHP script in OptimizePress Upload Directory Possible WebShell Access"; flow:to_server,established; content:"/wp-content/uploads/optpress/images_"; http_uri; fast_pattern:16,20; content:".php"; http_uri; pcre:"/\/wp-content\/uploads\/optpress\/images\_(?:comingsoon|lncthumbs|optbuttons)\/.*?\.php/Ui"; metadata: former_category CURRENT_EVENTS; reference:url,blog.sucuri.net/2013/12/wordpress-optimizepress-theme-file-upload-vulnerability.html; classtype:attempted-admin; sid:2017854; rev:3; metadata:created_at 2013_12_13, updated_at 2017_11_28;)

# 2017854
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET ATTACK_RESPONSE PHP script in OptimizePress Upload Directory Possible WebShell Access"; flow:to_server,established; content:"/wp-content/uploads/optpress/images_"; http_uri; fast_pattern:16,20; content:".php"; http_uri; pcre:"/\/wp-content\/uploads\/optpress\/images\_(?:comingsoon|lncthumbs|optbuttons)\/.*?\.php/Ui"; metadata: former_category CURRENT_EVENTS; reference:url,blog.sucuri.net/2013/12/wordpress-optimizepress-theme-file-upload-vulnerability.html; classtype:attempted-admin; sid:2017854; rev:3; metadata:created_at 2013_12_13, updated_at 2017_11_28;)
` 

Name : **PHP script in OptimizePress Upload Directory Possible WebShell Access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,blog.sucuri.net/2013/12/wordpress-optimizepress-theme-file-upload-vulnerability.html

CVE reference : Not defined

Creation date : 2013-12-13

Last modified date : 2017-11-28

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Linksys Router Returning Device Settings To External Source"; flow:established,from_server; file_data; content:"<GetDeviceSettingsResponse>"; content:"<GetDeviceSettingsResult>"; content:"<ModelName>"; metadata: former_category CURRENT_EVENTS; reference:url,isc.sans.edu/forums/diary/Linksys+Worm+TheMoon+Summary+What+we+know+so+far/17633; classtype:attempted-admin; sid:2018136; rev:3; metadata:created_at 2014_02_13, updated_at 2017_11_28;)

# 2018136
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Linksys Router Returning Device Settings To External Source"; flow:established,from_server; file_data; content:"<GetDeviceSettingsResponse>"; content:"<GetDeviceSettingsResult>"; content:"<ModelName>"; metadata: former_category CURRENT_EVENTS; reference:url,isc.sans.edu/forums/diary/Linksys+Worm+TheMoon+Summary+What+we+know+so+far/17633; classtype:attempted-admin; sid:2018136; rev:3; metadata:created_at 2014_02_13, updated_at 2017_11_28;)
` 

Name : **Linksys Router Returning Device Settings To External Source** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,isc.sans.edu/forums/diary/Linksys+Worm+TheMoon+Summary+What+we+know+so+far/17633

CVE reference : Not defined

Creation date : 2014-02-13

Last modified date : 2017-11-28

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http [$HOME_NET,$HTTP_SERVERS] any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Zone-H.org defacement notification"; flow:established,to_server; content:"POST"; http_method; content:"/notify/"; http_uri; pcre:"/\/notify\/(single|mass)$/iU"; content:"defacer|3d|"; http_client_body; depth:8; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/bin/view/Main/2001616; classtype:trojan-activity; sid:2001616; rev:14; metadata:created_at 2010_07_30, updated_at 2017_12_20;)

# 2001616
`alert http [$HOME_NET,$HTTP_SERVERS] any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Zone-H.org defacement notification"; flow:established,to_server; content:"POST"; http_method; content:"/notify/"; http_uri; pcre:"/\/notify\/(single|mass)$/iU"; content:"defacer|3d|"; http_client_body; depth:8; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/bin/view/Main/2001616; classtype:trojan-activity; sid:2001616; rev:14; metadata:created_at 2010_07_30, updated_at 2017_12_20;)
` 

Name : **Zone-H.org defacement notification** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2001616

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-12-20

Rev version : 14

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE WSO - WebShell Activity - WSO Title"; flow:established,to_client; file_data; content:"<title>"; content:" - WSO "; fast_pattern; distance:0; content:"</title>"; distance:0; metadata: former_category CURRENT_EVENTS; classtype:attempted-user; sid:2015905; rev:3; metadata:created_at 2012_11_21, updated_at 2018_01_08;)

# 2015905
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE WSO - WebShell Activity - WSO Title"; flow:established,to_client; file_data; content:"<title>"; content:" - WSO "; fast_pattern; distance:0; content:"</title>"; distance:0; metadata: former_category CURRENT_EVENTS; classtype:attempted-user; sid:2015905; rev:3; metadata:created_at 2012_11_21, updated_at 2018_01_08;)
` 

Name : **WSO - WebShell Activity - WSO Title** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2018-01-08

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE WSO - WebShell Activity - POST structure"; flow:established,to_server; content:"POST"; http_method; content:"&c="; http_client_body; content:"&p1="; http_client_body; content:"&p2="; http_client_body; content:"&p3="; http_client_body; fast_pattern; pcre:"/a=(?:S(?:e(?:lfRemove|cInfo)|tringTools|afeMode|ql)|(?:Bruteforc|Consol)e|FilesMan|Network|Logout|Php)/P"; metadata: former_category CURRENT_EVENTS; classtype:attempted-user; sid:2015906; rev:3; metadata:created_at 2012_11_21, updated_at 2018_01_08;)

# 2015906
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE WSO - WebShell Activity - POST structure"; flow:established,to_server; content:"POST"; http_method; content:"&c="; http_client_body; content:"&p1="; http_client_body; content:"&p2="; http_client_body; content:"&p3="; http_client_body; fast_pattern; pcre:"/a=(?:S(?:e(?:lfRemove|cInfo)|tringTools|afeMode|ql)|(?:Bruteforc|Consol)e|FilesMan|Network|Logout|Php)/P"; metadata: former_category CURRENT_EVENTS; classtype:attempted-user; sid:2015906; rev:3; metadata:created_at 2012_11_21, updated_at 2018_01_08;)
` 

Name : **WSO - WebShell Activity - POST structure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-11-21

Last modified date : 2018-01-08

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE passwd file Outbound from WEB SERVER Linux"; flow:established,from_server; file_data; content:"root:x:0:0:root:/root:/bin/"; within:27; classtype:successful-recon-limited; sid:2025879; rev:1; metadata:created_at 2018_07_20, updated_at 2018_07_20;)

# 2025879
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE passwd file Outbound from WEB SERVER Linux"; flow:established,from_server; file_data; content:"root:x:0:0:root:/root:/bin/"; within:27; classtype:successful-recon-limited; sid:2025879; rev:1; metadata:created_at 2018_07_20, updated_at 2018_07_20;)
` 

Name : **passwd file Outbound from WEB SERVER Linux** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-07-20

Last modified date : 2018-07-20

Rev version : 1

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Request"; flow:established,from_server; content:"Thanks Snailsor,FuYu,BloodSword"; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009146; classtype:web-application-activity; sid:2009146; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009146
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Request"; flow:established,from_server; content:"Thanks Snailsor,FuYu,BloodSword"; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009146; classtype:web-application-activity; sid:2009146; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible ASPXSpy Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,doc.emergingthreats.net/2009146

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Related Activity"; flow:established,from_server; content:"public string Password|3D 22|21232f297a57a5a743894a0e4a801fc3|22 3B|"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009147; classtype:web-application-activity; sid:2009147; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009147
`#alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Related Activity"; flow:established,from_server; content:"public string Password|3D 22|21232f297a57a5a743894a0e4a801fc3|22 3B|"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009147; classtype:web-application-activity; sid:2009147; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible ASPXSpy Related Activity** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,doc.emergingthreats.net/2009147

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Upload Attempt"; flow:established,to_server; content:"public string Password|3D 22|21232f297a57a5a743894a0e4a801fc3|22 3B|"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009149; classtype:web-application-activity; sid:2009149; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009149
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET ATTACK_RESPONSE Possible ASPXSpy Upload Attempt"; flow:established,to_server; content:"public string Password|3D 22|21232f297a57a5a743894a0e4a801fc3|22 3B|"; nocase; metadata: former_category ATTACK_RESPONSE; reference:url,doc.emergingthreats.net/2009149; classtype:web-application-activity; sid:2009149; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible ASPXSpy Upload Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,doc.emergingthreats.net/2009149

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (V3LU9) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"V3LU9"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026920; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026920
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (V3LU9) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"V3LU9"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026920; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (V3LU9) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (ctT2J) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"ctT2J"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026921; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026921
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (ctT2J) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"ctT2J"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026921; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (ctT2J) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (dy1PYmp) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dy1PYmp"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026922; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026922
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (dy1PYmp) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dy1PYmp"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026922; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (dy1PYmp) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (V3LU9iam) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"V3LU9iam"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026923; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026923
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (V3LU9iam) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"V3LU9iam"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026923; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (V3LU9iam) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (XctT2JqZW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"XctT2JqZW"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026924; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026924
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (XctT2JqZW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"XctT2JqZW"; fast_pattern; distance:0; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026924; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (XctT2JqZW) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (dy1PYmplY3) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dy1PYmplY3"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026925; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026925
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded New-Object (dy1PYmplY3) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dy1PYmplY3"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026925; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded New-Object (dy1PYmplY3) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (FydC1Qcm9) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"FydC1Qcm9"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026926; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026926
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (FydC1Qcm9) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"FydC1Qcm9"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026926; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (FydC1Qcm9) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJ) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"RhcnQtUHJ"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026927; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026927
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJ) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"RhcnQtUHJ"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026927; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJ) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2N) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJ0LVByb2N"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026928; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026928
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2N) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJ0LVByb2N"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026928; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2N) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJvY2) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"RhcnQtUHJvY2"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026929; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026929
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJvY2) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"RhcnQtUHJvY2"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026929; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (RhcnQtUHJvY2) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (GFydC1Qcm9jZX) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GFydC1Qcm9jZX"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026930; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026930
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (GFydC1Qcm9jZX) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GFydC1Qcm9jZX"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026930; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (GFydC1Qcm9jZX) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2Nlc3) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJ0LVByb2Nlc3"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026931; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026931
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2Nlc3) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJ0LVByb2Nlc3"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026931; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Start-Process (YXJ0LVByb2Nlc3) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (Zva2UtV21pTWV) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"Zva2UtV21pTWV"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026932; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026932
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (Zva2UtV21pTWV) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"Zva2UtV21pTWV"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026932; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (Zva2UtV21pTWV) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLVdtaU1"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026933; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026933
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLVdtaU1"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026933; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXR) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1XbWlNZXR"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026934; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026934
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXR) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1XbWlNZXR"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026934; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXR) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1ldG) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLVdtaU1ldG"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026935; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026935
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1ldG) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLVdtaU1ldG"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026935; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (52b2tlLVdtaU1ldG) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (nZva2UtV21pTWV0aG) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"nZva2UtV21pTWV0aG"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026936; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026936
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (nZva2UtV21pTWV0aG) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"nZva2UtV21pTWV0aG"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026936; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (nZva2UtV21pTWV0aG) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXRob2) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1XbWlNZXRob2"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026937; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026937
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXRob2) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1XbWlNZXRob2"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026937; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-WmiMethod (dm9rZS1XbWlNZXRob2) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (Zva2UtQ29) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"Zva2UtQ29"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026938; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026938
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (Zva2UtQ29) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"Zva2UtQ29"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026938; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (Zva2UtQ29) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1Db21"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026939; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026939
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1Db21"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026939; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (nZva2UtQ29tbW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"nZva2UtQ29tbW"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026940; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026940
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (nZva2UtQ29tbW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"nZva2UtQ29tbW"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026940; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (nZva2UtQ29tbW) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLUNvbW1"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026941; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026941
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLUNvbW1"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026941; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21tYW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1Db21tYW"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026942; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026942
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21tYW) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"dm9rZS1Db21tYW"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026942; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (dm9rZS1Db21tYW) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1hbm) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLUNvbW1hbm"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026943; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)

# 2026943
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1hbm) in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"52b2tlLUNvbW1hbm"; distance:0; fast_pattern; metadata: former_category CURRENT_EVENTS; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2026943; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_02_19, malware_family DNSlivery, updated_at 2019_02_19;)
` 

Name : **PowerShell Execution String Base64 Encoded Invoke-Command (52b2tlLUNvbW1hbm) in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-02-19

Last modified date : 2019-02-19

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"hpcyBwcm9"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027027; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027027
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"hpcyBwcm9"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027027; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"lzIHByb2d"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027028; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027028
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"lzIHByb2d"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027028; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aXMgcHJvZ3J"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027029; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027029
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aXMgcHJvZ3J"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027029; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"hpcyBwcm9ncm"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027030; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027030
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"hpcyBwcm9ncm"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027030; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GlzIHByb2dyYW"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027031; rev:2; metadata:attack_target DNS_Server, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027031
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GlzIHByb2dyYW"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027031; rev:2; metadata:attack_target DNS_Server, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 string /This Program/ in DNS TXT Reponse** 

Attack target : DNS_Server

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aXMgcHJvZ3JhbS"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027032; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)

# 2027032
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aXMgcHJvZ3JhbS"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027032; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 string /This Program/ in DNS TXT Reponse** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"gAaQBzACAAcAByAG8AZwByAGE"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027033; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027033
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"gAaQBzACAAcAByAG8AZwByAGE"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027033; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"BoAGkAcwAgAHAAcgBvAGcAcgB"; distance:0; fast_pattern; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027034; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)

# 2027034
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"BoAGkAcwAgAHAAcgBvAGcAcgB"; distance:0; fast_pattern; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027034; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aABpAHMAIABwAHIAbwBnAHIAYQB"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027035; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027035
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aABpAHMAIABwAHIAbwBnAHIAYQB"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027035; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"BoAGkAcwAgAHAAcgBvAGcAcgBhAG"; distance:0; fast_pattern; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027036; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)

# 2027036
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"BoAGkAcwAgAHAAcgBvAGcAcgBhAG"; distance:0; fast_pattern; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027036; rev:2; metadata:created_at 2019_03_05, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GgAaQBzACAAcAByAG8AZwByAGEAbQ"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027037; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027037
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"GgAaQBzACAAcAByAG8AZwByAGEAbQ"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027037; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aABpAHMAIABwAHIAbwBnAHIAYQBtAC"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027038; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family CoinMiner, updated_at 2019_03_05;)

# 2027038
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"aABpAHMAIABwAHIAbwBnAHIAYQBtAC"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027038; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family CoinMiner, updated_at 2019_03_05;)
` 

Name : **UTF16-LE base64 wide string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : CoinMiner

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"FyZ29ycCB"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027039; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027039
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"FyZ29ycCB"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027039; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"1hcmdvcnA"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027040; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027040
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"1hcmdvcnA"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027040; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJnb3JwIHN"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027041; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027041
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF8 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJnb3JwIHN"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027041; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF8 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"1hcmdvcnAgc2"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027042; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027042
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"1hcmdvcnAgc2"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027042; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"WFyZ29ycCBzaW"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027043; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027043
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"WFyZ29ycCBzaW"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027043; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJnb3JwIHNpaF"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027044; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)

# 2027044
`alert dns any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE UTF16 base64 reversed string /This Program/ in DNS TXT Reponse"; content:"|00 00 10 00 01 c0 0c 00 10 00 01|"; content:"YXJnb3JwIHNpaF"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/no0be/DNSlivery; classtype:bad-unknown; sid:2027044; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_03_05, malware_family DNSlivery, updated_at 2019_03_05;)
` 

Name : **UTF16 base64 reversed string /This Program/ in DNS TXT Reponse** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : url,github.com/no0be/DNSlivery

CVE reference : Not defined

Creation date : 2019-03-05

Last modified date : 2019-03-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : DNSlivery

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET [1024:] (msg:"ET ATTACK_RESPONSE LaZagne Artifact Outbound in FTP"; flow:established,to_server; content:"The LaZagne Project"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/AlessandroZ/LaZagne; classtype:trojan-activity; sid:2027151; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_04_04, malware_family Stealer, malware_family LaZange, updated_at 2019_04_04;)

# 2027151
`alert tcp $HOME_NET any -> $EXTERNAL_NET [1024:] (msg:"ET ATTACK_RESPONSE LaZagne Artifact Outbound in FTP"; flow:established,to_server; content:"The LaZagne Project"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,github.com/AlessandroZ/LaZagne; classtype:trojan-activity; sid:2027151; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2019_04_04, malware_family Stealer, malware_family LaZange, updated_at 2019_04_04;)
` 

Name : **LaZagne Artifact Outbound in FTP** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : trojan-activity

URL reference : url,github.com/AlessandroZ/LaZagne

CVE reference : Not defined

Creation date : 2019-04-04

Last modified date : 2019-04-04

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Stealer

Type : SID

Performance Impact : Not defined



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M1"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|IKEEXT"; content:"copy|20|wlbsctrl.dll"; content:"|5c|Windows|5c|System32|5c|wlbsctrl.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027232; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)

# 2027232
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M1"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|IKEEXT"; content:"copy|20|wlbsctrl.dll"; content:"|5c|Windows|5c|System32|5c|wlbsctrl.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027232; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command Inbound via HTTP M1** 

Attack target : Client_and_Server

Description : Alerts on an inbound script containing snippets indicative of Windows Service Control Manager DLL search order hijacking.

Tags : T1038

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-21

Last modified date : 2019-04-22

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M2"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|SessionEnv"; content:"copy|20|TSMSISrv.dll"; content:"|5c|Windows|5c|System32|5c|TSMSISrv.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027233; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)

# 2027233
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M2"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|SessionEnv"; content:"copy|20|TSMSISrv.dll"; content:"|5c|Windows|5c|System32|5c|TSMSISrv.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027233; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command Inbound via HTTP M2** 

Attack target : Client_and_Server

Description : Alerts on an inbound script containing snippets indicative of Windows Service Control Manager DLL search order hijacking.

Tags : T1038

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-21

Last modified date : 2019-04-22

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M1"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|I|00|K|00|E|00|E|00|X|00|T|00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|w|00|l|00|b|00|s|00|c|00|t|00|r|00|l|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|w|00|l|00|b|00|s|00|c|00|t|00|r|00|l|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027234; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)

# 2027234
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M1"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|I|00|K|00|E|00|E|00|X|00|T|00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|w|00|l|00|b|00|s|00|c|00|t|00|r|00|l|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|w|00|l|00|b|00|s|00|c|00|t|00|r|00|l|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027234; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M1** 

Attack target : Client_and_Server

Description : Alerts on an inbound script containing snippets indicative of Windows Service Control Manager DLL search order hijacking.

Tags : T1038

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-21

Last modified date : 2019-04-22

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M2"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|S|00|e|00|s|00|s|00|i|00|o|00|n|00|E|00|n|00|v|00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027235; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)

# 2027235
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M2"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|S|00|e|00|s|00|s|00|i|00|o|00|n|00|E|00|n|00|v|00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027235; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, tag T1038, signature_severity Major, created_at 2019_04_21, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M2** 

Attack target : Client_and_Server

Description : Alerts on an inbound script containing snippets indicative of Windows Service Control Manager DLL search order hijacking.

Tags : T1038

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-21

Last modified date : 2019-04-22

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M3"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|"; content:"copy|20|TSVIPSrv.dll"; content:"|5c|Windows|5c|System32|5c|TSVIPSrv.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027236; rev:2; metadata:created_at 2019_04_22, updated_at 2019_04_22;)

# 2027236
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command Inbound via HTTP M3"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"stop|20|"; content:"copy|20|TSVIPSrv.dll"; content:"|5c|Windows|5c|System32|5c|TSVIPSrv.dll"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027236; rev:2; metadata:created_at 2019_04_22, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command Inbound via HTTP M3** 

Attack target : Not defined

Description : Detects the copying of a specially crafted .dll to a path observed loading SCM DLLs

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-22

Last modified date : 2019-04-22

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M3"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|T|00|S|00|V|00|I|00|P|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027238; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, signature_severity Major, created_at 2019_04_22, performance_impact Low, updated_at 2019_04_22;)

# 2027238
`alert http any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M3"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|00|s|00|t|00|o|00|p|00 20 00|"; content:"|00|c|00|o|00|p|00|y|00 20 00|T|00|S|00|V|00|I|00|P|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; content:"|00 5c 00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00 5c 00|T|00|S|00|M|00|S|00|I|00|S|00|r|00|v|00|.|00|d|00|l|00|l|00|"; distance:0; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027238; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_and_Server, deployment Perimeter, signature_severity Major, created_at 2019_04_22, performance_impact Low, updated_at 2019_04_22;)
` 

Name : **Windows SCM DLL Hijack Command (UTF-16) Inbound via HTTP M3** 

Attack target : Client_and_Server

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-22

Last modified date : 2019-04-22

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert smb any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible Lateral Movement - File Creation Request in Remote System32 Directory (T1105)"; flow:established,to_server; content:"|05 00|"; offset:16; depth:2; content:"|00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00|"; fast_pattern; metadata: former_category ATTACK_RESPONSE; classtype:attempted-user; sid:2027267; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Internal, tag T1105, tag lateral_movement, tag remote_file_copy, signature_severity Major, created_at 2019_04_23, performance_impact Low, updated_at 2019_04_23;)

# 2027267
`alert smb any any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible Lateral Movement - File Creation Request in Remote System32 Directory (T1105)"; flow:established,to_server; content:"|05 00|"; offset:16; depth:2; content:"|00|W|00|i|00|n|00|d|00|o|00|w|00|s|00 5c 00|S|00|y|00|s|00|t|00|e|00|m|00|3|00|2|00|"; fast_pattern; metadata: former_category ATTACK_RESPONSE; classtype:attempted-user; sid:2027267; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Internal, tag T1105, tag lateral_movement, tag remote_file_copy, signature_severity Major, created_at 2019_04_23, performance_impact Low, updated_at 2019_04_23;)
` 

Name : **Possible Lateral Movement - File Creation Request in Remote System32 Directory (T1105)** 

Attack target : Not defined

Description : Alerts on a File Creation attempt with the destination being System32 on a remote system.

Tags : lateral_movement, remote_file_copy, T1105

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2019-04-23

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible Remote System32 DLL Hijack Command Inbound via HTTP (T1038, T1105)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"copy|20|"; content:".dll"; distance:0; content:"|5c|Windows|5c|System32|5c|"; distance:0; fast_pattern; content:".dll"; distance:0; content:"copy|20|"; pcre:"/^(?P<dll_name>[a-z0-9\-_]{1,20})\.dll\s*\\\\(([0-9]{1,3}\.){3}[0-9]{1,3}|([a-z0-9\-]{1,30}\.){1,8}[a-z]{1,8})\\\w{1,10}\$\\Windows\\System32\\(?P=dll_name)\.dll/Ri"; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027268; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Internal, tag T1038, tag T1105, signature_severity Major, created_at 2019_04_23, performance_impact Low, updated_at 2019_04_23;)

# 2027268
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible Remote System32 DLL Hijack Command Inbound via HTTP (T1038, T1105)"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"copy|20|"; content:".dll"; distance:0; content:"|5c|Windows|5c|System32|5c|"; distance:0; fast_pattern; content:".dll"; distance:0; content:"copy|20|"; pcre:"/^(?P<dll_name>[a-z0-9\-_]{1,20})\.dll\s*\\\\(([0-9]{1,3}\.){3}[0-9]{1,3}|([a-z0-9\-]{1,30}\.){1,8}[a-z]{1,8})\\\w{1,10}\$\\Windows\\System32\\(?P=dll_name)\.dll/Ri"; metadata: former_category ATTACK_RESPONSE; reference:url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992; classtype:attempted-user; sid:2027268; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Internal, tag T1038, tag T1105, signature_severity Major, created_at 2019_04_23, performance_impact Low, updated_at 2019_04_23;)
` 

Name : **Possible Remote System32 DLL Hijack Command Inbound via HTTP (T1038, T1105)** 

Attack target : Not defined

Description : Alerts on an inbound command that attempts to copy a .dll file to a remote System32 directory, indicative of remote SCM DLL hijack techniques.

Tags : T1038, T1105

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

CVE reference : Not defined

Creation date : 2019-04-23

Last modified date : 2019-04-23

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Windows 64bit procdump Dump File Exfiltration"; flow:established,to_server; content:"|00 2a 00 2a 00 2a 00 20 00|p|00|r|00|o|00|c|00|d|00|u|00|m|00|p|00|6|00|4|00 2e 00|e|00|x|00|e"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,attack.mitre.org/techniques/T1003/; classtype:attempted-admin; sid:2027435; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, tag T1003, tag credential_dumping, signature_severity Major, created_at 2019_06_05, performance_impact Low, updated_at 2019_06_05;)

# 2027435
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Windows 64bit procdump Dump File Exfiltration"; flow:established,to_server; content:"|00 2a 00 2a 00 2a 00 20 00|p|00|r|00|o|00|c|00|d|00|u|00|m|00|p|00|6|00|4|00 2e 00|e|00|x|00|e"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,attack.mitre.org/techniques/T1003/; classtype:attempted-admin; sid:2027435; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, tag T1003, tag credential_dumping, signature_severity Major, created_at 2019_06_05, performance_impact Low, updated_at 2019_06_05;)
` 

Name : **Windows 64bit procdump Dump File Exfiltration** 

Attack target : Not defined

Description : Alerts on an outbound TCP packet containing a procdump.

Tags : credential_dumping, T1003

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-admin

URL reference : url,attack.mitre.org/techniques/T1003/

CVE reference : Not defined

Creation date : 2019-06-05

Last modified date : 2019-06-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Windows 32bit procdump Dump File Exfiltration"; flow:established,to_server; content:"|00 2a 00 2a 00 2a 00 20 00|p|00|r|00|o|00|c|00|d|00|u|00|m|00|p|00 2e 00|e|00|x|00|e"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,attack.mitre.org/techniques/T1003/; classtype:attempted-admin; sid:2027436; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, tag T1003, tag credential_dumping, signature_severity Major, created_at 2019_06_05, performance_impact Low, updated_at 2019_06_05;)

# 2027436
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Windows 32bit procdump Dump File Exfiltration"; flow:established,to_server; content:"|00 2a 00 2a 00 2a 00 20 00|p|00|r|00|o|00|c|00|d|00|u|00|m|00|p|00 2e 00|e|00|x|00|e"; fast_pattern; metadata: former_category ATTACK_RESPONSE; reference:url,attack.mitre.org/techniques/T1003/; classtype:attempted-admin; sid:2027436; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, deployment Perimeter, tag T1003, tag credential_dumping, signature_severity Major, created_at 2019_06_05, performance_impact Low, updated_at 2019_06_05;)
` 

Name : **Windows 32bit procdump Dump File Exfiltration** 

Attack target : Not defined

Description : Alerts on an outbound TCP packet containing procdump.

Tags : credential_dumping, T1003

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-admin

URL reference : url,attack.mitre.org/techniques/T1003/

CVE reference : Not defined

Creation date : 2019-06-05

Last modified date : 2019-06-05

Rev version : 2

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL ATTACK_RESPONSE directory listing"; flow:to_server,established; content:"/ServerVariables_Jscript.asp"; http_uri; nocase; reference:nessus,10573; classtype:web-application-attack; sid:2101009; rev:9; metadata:created_at 2010_09_23, updated_at 2019_08_22;)

# 2101009
`alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"GPL ATTACK_RESPONSE directory listing"; flow:to_server,established; content:"/ServerVariables_Jscript.asp"; http_uri; nocase; reference:nessus,10573; classtype:web-application-attack; sid:2101009; rev:9; metadata:created_at 2010_09_23, updated_at 2019_08_22;)
` 

Name : **directory listing** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : nessus,10573

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-08-22

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows LMHosts File Download - Likely DNSChanger Infection"; flow:established,to_client; content:"#|0d 0a|#|20|This|20|is|20|a|20|sample|20|HOSTS|20|file|20|used|20|by|20|Microsoft|20|TCP/IP|20|for|20|Windows.|0d 0a|#|0d 0a|#|20|This|20|file|20|contains|20|the|20|mappings|20|of|20|IP|20|addresses|20|to|20|host|20|names."; reference:url,doc.emergingthreats.net/bin/view/Main/2008559; classtype:trojan-activity; sid:2008559; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2008559
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Windows LMHosts File Download - Likely DNSChanger Infection"; flow:established,to_client; content:"#|0d 0a|#|20|This|20|is|20|a|20|sample|20|HOSTS|20|file|20|used|20|by|20|Microsoft|20|TCP/IP|20|for|20|Windows.|0d 0a|#|0d 0a|#|20|This|20|file|20|contains|20|the|20|mappings|20|of|20|IP|20|addresses|20|to|20|host|20|names."; reference:url,doc.emergingthreats.net/bin/view/Main/2008559; classtype:trojan-activity; sid:2008559; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Windows LMHosts File Download - Likely DNSChanger Infection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2008559

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE r57 phpshell footer detected"; flow:established,from_server; content:"r57shell - http-shell by RST/GHC"; reference:url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755; reference:url,doc.emergingthreats.net/bin/view/Main/2003535; classtype:web-application-activity; sid:2003535; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2003535
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE r57 phpshell footer detected"; flow:established,from_server; content:"r57shell - http-shell by RST/GHC"; reference:url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755; reference:url,doc.emergingthreats.net/bin/view/Main/2003535; classtype:web-application-activity; sid:2003535; rev:8; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **r57 phpshell footer detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.pestpatrol.com/spywarecenter/pest.aspx?id=453096755|url,doc.emergingthreats.net/bin/view/Main/2003535

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 8

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE x2300 phpshell detected"; flow:established,from_server; content:"x2300 Locus7Shell"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007651; classtype:web-application-activity; sid:2007651; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2007651
`alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE x2300 phpshell detected"; flow:established,from_server; content:"x2300 Locus7Shell"; reference:url,www.rfxn.com/vdb.php; reference:url,doc.emergingthreats.net/bin/view/Main/2007651; classtype:web-application-activity; sid:2007651; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **x2300 phpshell detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,www.rfxn.com/vdb.php|url,doc.emergingthreats.net/bin/view/Main/2007651

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (BSD style)"; flow:established,from_server; file_data; content:"root|3a|*|3a|0|3a|0|3a|"; nocase; content:"|3a|/root|3a|/bin"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003071; classtype:successful-recon-limited; sid:2003071; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2003071
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (BSD style)"; flow:established,from_server; file_data; content:"root|3a|*|3a|0|3a|0|3a|"; nocase; content:"|3a|/root|3a|/bin"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2003071; classtype:successful-recon-limited; sid:2003071; rev:9; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Possible /etc/passwd via HTTP (BSD style)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : successful-recon-limited

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003071

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 9

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $SQL_SERVERS 3306 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL User Account Enumeration"; flow:from_server,established; content:"|02|"; offset:3; depth:4; content:"|15 04|Access denied for user"; fast_pattern; threshold:type both,track by_dst,count 10,seconds 1; reference:url,seclists.org/fulldisclosure/2012/Dec/att-9/; classtype:protocol-command-decode; sid:2015993; rev:3; metadata:created_at 2012_12_05, updated_at 2019_10_07;)

# 2015993
`alert tcp $SQL_SERVERS 3306 -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE MySQL User Account Enumeration"; flow:from_server,established; content:"|02|"; offset:3; depth:4; content:"|15 04|Access denied for user"; fast_pattern; threshold:type both,track by_dst,count 10,seconds 1; reference:url,seclists.org/fulldisclosure/2012/Dec/att-9/; classtype:protocol-command-decode; sid:2015993; rev:3; metadata:created_at 2012_12_05, updated_at 2019_10_07;)
` 

Name : **MySQL User Account Enumeration** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : protocol-command-decode

URL reference : url,seclists.org/fulldisclosure/2012/Dec/att-9/

CVE reference : Not defined

Creation date : 2012-12-05

Last modified date : 2019-10-07

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Matahari client"; flow:to_server,established; content:"Accept|2d|Encoding|3a 20|identity|0d 0a|"; http_header; content:"Next|2d|Polling"; http_header;  fast_pattern; content:"Content|2d|Salt|3a 20|"; http_header; pcre:"/Content\x2dSalt\x3a\x20[0-9\.\-]+\x0d\x0a/Hi"; reference:url,doc.emergingthreats.net/2010795; classtype:trojan-activity; sid:2010795; rev:11; metadata:created_at 2010_07_30, updated_at 2019_10_07;)

# 2010795
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ATTACK_RESPONSE Matahari client"; flow:to_server,established; content:"Accept|2d|Encoding|3a 20|identity|0d 0a|"; http_header; content:"Next|2d|Polling"; http_header;  fast_pattern; content:"Content|2d|Salt|3a 20|"; http_header; pcre:"/Content\x2dSalt\x3a\x20[0-9\.\-]+\x0d\x0a/Hi"; reference:url,doc.emergingthreats.net/2010795; classtype:trojan-activity; sid:2010795; rev:11; metadata:created_at 2010_07_30, updated_at 2019_10_07;)
` 

Name : **Matahari client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2010795

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-10-07

Rev version : 11

Category : ATTACK_RESPONSE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Reverse HTTPS certificate"; flow:from_server,established; content:"|A3 0D 30 0B 30 09 06 03 55 1D 13 04 02 30 00|"; fast_pattern; content:"|16 03 03|"; pcre:"/^..\x0B.{9}\x30\x82..\x30\x82..\xA0\x03\x02\x01\x02\x02(?:\x09.{9}|\x08.{8})/Rs"; content:"|30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 30|"; within:16; pcre:"/^.\x31.\x30.\x06\x03\x55\x04\x03\x0C.([a-z]{2,9})\x30.\x17\x0D[0-9]{12}Z\x17\x0D[0-9]{12}Z\x30.\x31.\x30.\x06\x03\x55\x04\x03\x0C.\g{1}\x30\x82../Rs"; content:"|30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82|"; within:17; pcre:"/^...\x30\x82..\x02\x82...{256,257}/Rs"; content:"|02 03 01 00 01 A3 0D 30 0B 30 09 06 03 55 1D 13 04 02 30 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00|"; within:36; content:!"|06|ubuntu"; content:!"|04|mint"; content:!"|a9 d5 73 d2 a0 a5 a1 69|"; reference:url,blog.didierstevens.com/2015/05/11/detecting-network-traffic-from-metasploits-meterpreter-reverse-http-module; classtype:trojan-activity; sid:2021178; rev:7; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2015_06_03, updated_at 2019_10_07;)

# 2021178
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Metasploit Meterpreter Reverse HTTPS certificate"; flow:from_server,established; content:"|A3 0D 30 0B 30 09 06 03 55 1D 13 04 02 30 00|"; fast_pattern; content:"|16 03 03|"; pcre:"/^..\x0B.{9}\x30\x82..\x30\x82..\xA0\x03\x02\x01\x02\x02(?:\x09.{9}|\x08.{8})/Rs"; content:"|30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 30|"; within:16; pcre:"/^.\x31.\x30.\x06\x03\x55\x04\x03\x0C.([a-z]{2,9})\x30.\x17\x0D[0-9]{12}Z\x17\x0D[0-9]{12}Z\x30.\x31.\x30.\x06\x03\x55\x04\x03\x0C.\g{1}\x30\x82../Rs"; content:"|30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82|"; within:17; pcre:"/^...\x30\x82..\x02\x82...{256,257}/Rs"; content:"|02 03 01 00 01 A3 0D 30 0B 30 09 06 03 55 1D 13 04 02 30 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00|"; within:36; content:!"|06|ubuntu"; content:!"|04|mint"; content:!"|a9 d5 73 d2 a0 a5 a1 69|"; reference:url,blog.didierstevens.com/2015/05/11/detecting-network-traffic-from-metasploits-meterpreter-reverse-http-module; classtype:trojan-activity; sid:2021178; rev:7; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2015_06_03, updated_at 2019_10_07;)
` 

Name : **Metasploit Meterpreter Reverse HTTPS certificate** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : trojan-activity

URL reference : url,blog.didierstevens.com/2015/05/11/detecting-network-traffic-from-metasploits-meterpreter-reverse-http-module

CVE reference : Not defined

Creation date : 2015-06-03

Last modified date : 2019-10-07

Rev version : 7

Category : ATTACK_RESPONSE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible BeEF HTTP Headers Inbound"; flow:established,from_server; content:"Content-Type|3a 20|text/javascript|0d 0a|Server|3a 20|Apache/2.2.3 (CentOS)|0d 0a|Pragma|3a|"; fast_pattern; http_header; depth:69; content:"|0d 0a|Expires|3a 20|0|0d 0a|"; http_header; http_header_names; content:!"Set-Cookie|0d 0a|"; content:!"X-Powered-By|0d 0a|"; metadata: former_category ATTACK_RESPONSE; classtype:attempted-user; sid:2024421; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_06_23, performance_impact Moderate, updated_at 2020_03_04;)

# 2024421
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE Possible BeEF HTTP Headers Inbound"; flow:established,from_server; content:"Content-Type|3a 20|text/javascript|0d 0a|Server|3a 20|Apache/2.2.3 (CentOS)|0d 0a|Pragma|3a|"; fast_pattern; http_header; depth:69; content:"|0d 0a|Expires|3a 20|0|0d 0a|"; http_header; http_header_names; content:!"Set-Cookie|0d 0a|"; content:!"X-Powered-By|0d 0a|"; metadata: former_category ATTACK_RESPONSE; classtype:attempted-user; sid:2024421; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_06_23, performance_impact Moderate, updated_at 2020_03_04;)
` 

Name : **Possible BeEF HTTP Headers Inbound** 

Attack target : Client_Endpoint

Description : Alerts on observed BeEF fake HTTP server headers

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2017-06-23

Last modified date : 2020-03-04

Rev version : 3

Category : ATTACK_RESPONSE

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Moderate


