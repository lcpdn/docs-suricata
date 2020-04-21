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



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Starcraft login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"RATS"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002101; classtype:policy-violation; sid:2002101; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002101
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Starcraft login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"RATS"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002101; classtype:policy-violation; sid:2002101; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Starcraft login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002101

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Brood War login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PXES"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002102; classtype:policy-violation; sid:2002102; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002102
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Brood War login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PXES"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002102; classtype:policy-violation; sid:2002102; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Brood War login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002102

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"LTRD"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002103; classtype:policy-violation; sid:2002103; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002103
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"LTRD"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002103; classtype:policy-violation; sid:2002103; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Diablo login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002103

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo 2 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"VD2D"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002104; classtype:policy-violation; sid:2002104; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002104
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo 2 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"VD2D"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002104; classtype:policy-violation; sid:2002104; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Diablo 2 login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002104

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo 2 Lord of Destruction login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PX2D"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002105; classtype:policy-violation; sid:2002105; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002105
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Diablo 2 Lord of Destruction login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PX2D"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002105; classtype:policy-violation; sid:2002105; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Diablo 2 Lord of Destruction login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002105

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 2 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"NB2W"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002106; classtype:policy-violation; sid:2002106; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002106
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 2 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"NB2W"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002106; classtype:policy-violation; sid:2002106; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Warcraft 2 login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002106

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 3 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"3RAW"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002107; classtype:policy-violation; sid:2002107; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002107
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 3 login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"3RAW"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002107; classtype:policy-violation; sid:2002107; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Warcraft 3 login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002107

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net old game version"; flow:established,from_server; content:"|FF 51|"; depth:2; content:"|00 01 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002109; classtype:policy-violation; sid:2002109; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002109
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net old game version"; flow:established,from_server; content:"|FF 51|"; depth:2; content:"|00 01 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002109; classtype:policy-violation; sid:2002109; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net old game version** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002109

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net invalid version"; flow:established,from_server; content:"|FF 51 08 00 01 01 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002110; classtype:policy-violation; sid:2002110; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002110
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net invalid version"; flow:established,from_server; content:"|FF 51 08 00 01 01 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002110; classtype:policy-violation; sid:2002110; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net invalid version** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002110

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net invalid cdkey"; flow:established,from_server; content:"|FF 51 09 00 00 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002111; classtype:policy-violation; sid:2002111; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002111
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net invalid cdkey"; flow:established,from_server; content:"|FF 51 09 00 00 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002111; classtype:policy-violation; sid:2002111; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net invalid cdkey** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002111

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net cdkey in use"; flow:established,from_server; content:"|FF 51|"; depth:2; content:"|01 02 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002112; classtype:policy-violation; sid:2002112; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002112
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net cdkey in use"; flow:established,from_server; content:"|FF 51|"; depth:2; content:"|01 02 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002112; classtype:policy-violation; sid:2002112; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net cdkey in use** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002112

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net banned key"; flow:established,from_server; content:"|FF 51 09 00 02 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002113; classtype:policy-violation; sid:2002113; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002113
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net banned key"; flow:established,from_server; content:"|FF 51 09 00 02 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002113; classtype:policy-violation; sid:2002113; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net banned key** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002113

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net wrong product"; flow:established,from_server; content:"|FF 51 09 00 03 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002114; classtype:policy-violation; sid:2002114; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002114
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net wrong product"; flow:established,from_server; content:"|FF 51 09 00 03 02 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002114; classtype:policy-violation; sid:2002114; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net wrong product** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002114

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user in channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|01 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002118; classtype:policy-violation; sid:2002118; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002118
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user in channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|01 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002118; classtype:policy-violation; sid:2002118; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net user in channel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002118

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user joined channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|02 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002140; classtype:policy-violation; sid:2002140; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002140
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user joined channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|02 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002140; classtype:policy-violation; sid:2002140; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net user joined channel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002140

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user left channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|03 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002141; classtype:policy-violation; sid:2002141; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002141
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user left channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|03 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002141; classtype:policy-violation; sid:2002141; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net user left channel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002141

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net received whisper message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|04 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002142; classtype:policy-violation; sid:2002142; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002142
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net received whisper message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|04 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002142; classtype:policy-violation; sid:2002142; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net received whisper message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002142

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net received server broadcast"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|06 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002143; classtype:policy-violation; sid:2002143; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002143
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net received server broadcast"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|06 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002143; classtype:policy-violation; sid:2002143; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net received server broadcast** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002143

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net joined channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|07 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002144; classtype:policy-violation; sid:2002144; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002144
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net joined channel"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|07 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002144; classtype:policy-violation; sid:2002144; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net joined channel** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002144

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user had a flags update"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|09 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002145; classtype:policy-violation; sid:2002145; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002145
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net user had a flags update"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|09 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002145; classtype:policy-violation; sid:2002145; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net user had a flags update** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002145

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net sent a whisper"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0a 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002146; classtype:policy-violation; sid:2002146; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002146
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net sent a whisper"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0a 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002146; classtype:policy-violation; sid:2002146; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net sent a whisper** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002146

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel full"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0d 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002147; classtype:policy-violation; sid:2002147; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002147
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel full"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0d 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002147; classtype:policy-violation; sid:2002147; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net channel full** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002147

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel doesn't exist"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0e 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002148; classtype:policy-violation; sid:2002148; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002148
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel doesn't exist"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0e 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002148; classtype:policy-violation; sid:2002148; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net channel doesn't exist** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002148

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel is restricted"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0f 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002149; classtype:policy-violation; sid:2002149; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002149
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net channel is restricted"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|0f 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002149; classtype:policy-violation; sid:2002149; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net channel is restricted** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002149

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net informational message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|12 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002150; classtype:policy-violation; sid:2002150; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002150
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net informational message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|12 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002150; classtype:policy-violation; sid:2002150; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net informational message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002150

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net error message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|13 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002151; classtype:policy-violation; sid:2002151; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002151
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net error message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|13 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002151; classtype:policy-violation; sid:2002151; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net error message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002151

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net 'emote' message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|17 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002152; classtype:policy-violation; sid:2002152; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002152
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net 'emote' message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|17 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002152; classtype:policy-violation; sid:2002152; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net 'emote' message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002152

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net outgoing chat message"; flow:established,to_server; content:"|FF 0E|"; depth:2; reference:url,doc.emergingthreats.net/bin/view/Main/2002119; classtype:policy-violation; sid:2002119; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002119
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net outgoing chat message"; flow:established,to_server; content:"|FF 0E|"; depth:2; reference:url,doc.emergingthreats.net/bin/view/Main/2002119; classtype:policy-violation; sid:2002119; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net outgoing chat message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002119

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 3724 (msg:"ET GAMES World of Warcraft connection"; flow:established,to_server; content:"|00|"; depth:1; content:"|25 00|WoW|00|"; distance:1; within:7; reference:url,doc.emergingthreats.net/bin/view/Main/2002138; classtype:policy-violation; sid:2002138; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002138
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 3724 (msg:"ET GAMES World of Warcraft connection"; flow:established,to_server; content:"|00|"; depth:1; content:"|25 00|WoW|00|"; distance:1; within:7; reference:url,doc.emergingthreats.net/bin/view/Main/2002138; classtype:policy-violation; sid:2002138; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **World of Warcraft connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002138

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 3724 -> $HOME_NET any (msg:"ET GAMES World of Warcraft failed logon"; flow:established,from_server; content:"|01 0A|"; depth:2; reference:url,doc.emergingthreats.net/bin/view/Main/2002139; classtype:policy-violation; sid:2002139; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002139
`#alert tcp $EXTERNAL_NET 3724 -> $HOME_NET any (msg:"ET GAMES World of Warcraft failed logon"; flow:established,from_server; content:"|01 0A|"; depth:2; reference:url,doc.emergingthreats.net/bin/view/Main/2002139; classtype:policy-violation; sid:2002139; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **World of Warcraft failed logon** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002139

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Guild Wars connection"; flow:established,to_server; content:"|01 00 00 00 00 F1 00 10 00 01 00 00 00 00 00 00 00 00 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002154; classtype:policy-violation; sid:2002154; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002154
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Guild Wars connection"; flow:established,to_server; content:"|01 00 00 00 00 F1 00 10 00 01 00 00 00 00 00 00 00 00 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002154; classtype:policy-violation; sid:2002154; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Guild Wars connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002154

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net incoming chat message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|05 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002170; classtype:policy-violation; sid:2002170; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002170
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net incoming chat message"; flow:established,from_server; content:"|FF 0F|"; depth:2; content:"|05 00 00 00|"; offset:4; depth:4; reference:url,doc.emergingthreats.net/bin/view/Main/2002170; classtype:policy-violation; sid:2002170; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net incoming chat message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002170

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET any -> $EXTERNAL_NET 27015 (msg:"ET GAMES Steam connection"; content:"getchallengesteam"; reference:url,doc.emergingthreats.net/bin/view/Main/2002155; classtype:policy-violation; sid:2002155; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002155
`#alert udp $HOME_NET any -> $EXTERNAL_NET 27015 (msg:"ET GAMES Steam connection"; content:"getchallengesteam"; reference:url,doc.emergingthreats.net/bin/view/Main/2002155; classtype:policy-violation; sid:2002155; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Steam connection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002155

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 27020:27050 (msg:"ET GAMES STEAM Connection (v2)"; flow:established,to_server; content:"|00 00 00 03|"; dsize:4; reference:url,doc.emergingthreats.net/bin/view/Main/2003089; classtype:policy-violation; sid:2003089; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003089
`alert tcp $HOME_NET any -> $EXTERNAL_NET 27020:27050 (msg:"ET GAMES STEAM Connection (v2)"; flow:established,to_server; content:"|00 00 00 03|"; dsize:4; reference:url,doc.emergingthreats.net/bin/view/Main/2003089; classtype:policy-violation; sid:2003089; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **STEAM Connection (v2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003089

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak3 Connect"; content:"|00 00 00 00 02 9d 74 8b 45 aa 7b ef b9 9e fe ad 08 19 ba cf 41 e0 16 a2|"; offset:8; depth:24; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011733; classtype:policy-violation; sid:2011733; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011733
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak3 Connect"; content:"|00 00 00 00 02 9d 74 8b 45 aa 7b ef b9 9e fe ad 08 19 ba cf 41 e0 16 a2|"; offset:8; depth:24; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011733; classtype:policy-violation; sid:2011733; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak3 Connect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011733

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Login"; content:"|f4 be 03 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011734; classtype:policy-violation; sid:2011734; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011734
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Login"; content:"|f4 be 03 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011734; classtype:policy-violation; sid:2011734; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Connection/Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011734

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Login Replay"; content:"|f4 be 04 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011735; classtype:policy-violation; sid:2011735; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011735
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Login Replay"; content:"|f4 be 04 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011735; classtype:policy-violation; sid:2011735; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Connection/Login Replay** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011735

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Ping"; content:"|f4 be 01 00|"; depth:4; threshold:type limit, count 1, seconds 300, track by_src; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011736; classtype:policy-violation; sid:2011736; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011736
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Ping"; content:"|f4 be 01 00|"; depth:4; threshold:type limit, count 1, seconds 300, track by_src; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011736; classtype:policy-violation; sid:2011736; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Connection/Ping** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011736

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Ping Reply"; content:"|f4 be 02 00|"; depth:4; threshold:type limit, count 1, seconds 300, track by_src; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011737; classtype:policy-violation; sid:2011737; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011737
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Connection/Ping Reply"; content:"|f4 be 02 00|"; depth:4; threshold:type limit, count 1, seconds 300, track by_src; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011737; classtype:policy-violation; sid:2011737; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Connection/Ping Reply** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011737

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Channel List"; content:"|f0 be 06 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011739; classtype:policy-violation; sid:2011739; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011739
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Channel List"; content:"|f0 be 06 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011739; classtype:policy-violation; sid:2011739; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Channel List** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011739

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Player List"; content:"|f0 be 07 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011740; classtype:policy-violation; sid:2011740; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011740
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Player List"; content:"|f0 be 07 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011740; classtype:policy-violation; sid:2011740; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Player List** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011740

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Login End"; content:"|f0 be 08 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011741; classtype:policy-violation; sid:2011741; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011741
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Login End"; content:"|f0 be 08 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011741; classtype:policy-violation; sid:2011741; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Login End** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011741

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/New Player Joined"; content:"|f0 be 64 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011742; classtype:policy-violation; sid:2011742; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011742
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/New Player Joined"; content:"|f0 be 64 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011742; classtype:policy-violation; sid:2011742; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/New Player Joined** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011742

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Player Left"; content:"|f0 be 65 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011743; classtype:policy-violation; sid:2011743; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011743
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Player Left"; content:"|f0 be 65 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011743; classtype:policy-violation; sid:2011743; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Player Left** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011743

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Change Status"; content:"|f0 be 30 01|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011744; classtype:policy-violation; sid:2011744; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011744
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Change Status"; content:"|f0 be 30 01|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011744; classtype:policy-violation; sid:2011744; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Change Status** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011744

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Known Player Update"; content:"|f0 be 68 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011745; classtype:policy-violation; sid:2011745; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011745
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Known Player Update"; content:"|f0 be 68 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011745; classtype:policy-violation; sid:2011745; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Known Player Update** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011745

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Disconnect"; content:"|f0 be 2c 01|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011746; classtype:policy-violation; sid:2011746; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011746
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Disconnect"; content:"|f0 be 2c 01|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011746; classtype:policy-violation; sid:2011746; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Disconnect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011746

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 ACK"; content:"|f1 be|"; depth:2; dsize:16; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011747; classtype:policy-violation; sid:2011747; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011747
`#alert udp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 ACK"; content:"|f1 be|"; depth:2; dsize:16; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011747; classtype:policy-violation; sid:2011747; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 ACK** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011747

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Ad Report"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/ad_report.php"; content:"|0d 0a|User-Agent|3a| GameBox"; uricontent:"protocol="; uricontent:"author="; uricontent:"login="; uricontent:"zone="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011758; classtype:policy-violation; sid:2011758; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011758
`#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Ad Report"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/ad_report.php"; content:"|0d 0a|User-Agent|3a| GameBox"; uricontent:"protocol="; uricontent:"author="; uricontent:"login="; uricontent:"zone="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011758; classtype:policy-violation; sid:2011758; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Ad Report** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011758

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 20000 (msg:"ET GAMES Gold VIP Club Casino Client in Use"; flow:established,to_server; dsize:25; content:"Gold VIP Club Casino"; reference:url,doc.emergingthreats.net/2007746; classtype:policy-violation; sid:2007746; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007746
`alert tcp $HOME_NET any -> $EXTERNAL_NET 20000 (msg:"ET GAMES Gold VIP Club Casino Client in Use"; flow:established,to_server; dsize:25; content:"Gold VIP Club Casino"; reference:url,doc.emergingthreats.net/2007746; classtype:policy-violation; sid:2007746; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gold VIP Club Casino Client in Use** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2007746

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Game Launch"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/launcher_init.php?"; content:"|0d 0a|User-Agent|3a| GameBox"; uricontent:"game="; uricontent:"lang="; uricontent:"protocol="; uricontent:"distro="; uricontent:"osdesc="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011748; classtype:policy-violation; sid:2011748; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011748
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Game Launch"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/launcher_init.php?"; content:"|0d 0a|User-Agent|3a| GameBox"; uricontent:"game="; uricontent:"lang="; uricontent:"protocol="; uricontent:"distro="; uricontent:"osdesc="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011748; classtype:policy-violation; sid:2011748; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Game Launch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011748

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Game Check for Patch"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/patch.php?"; uricontent:"game="; uricontent:"lang="; uricontent:"protocol="; uricontent:"distro="; uricontent:"osdesc="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011749; classtype:policy-violation; sid:2011749; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011749
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Game Check for Patch"; flow:to_server,established; content:"GET"; offset:0; depth:3; uricontent:"/online_game/patch.php?"; uricontent:"game="; uricontent:"lang="; uricontent:"protocol="; uricontent:"distro="; uricontent:"osdesc="; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011749; classtype:policy-violation; sid:2011749; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Game Check for Patch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011749

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetConnectionAndGameParams"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetConnectionAndGameParams</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011750; classtype:policy-violation; sid:2011750; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011750
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetConnectionAndGameParams"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetConnectionAndGameParams</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011750; classtype:policy-violation; sid:2011750; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request GetConnectionAndGameParams** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011750

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request OpenSession"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>OpenSession</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011751; classtype:policy-violation; sid:2011751; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011751
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request OpenSession"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>OpenSession</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011751; classtype:policy-violation; sid:2011751; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request OpenSession** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011751

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request Connect"; flow:to_server,established; content:"POST"; http_method; content:"/online_game/request.php"; http_uri; content:"User-Agent|3a| GameBox"; http_header; content:"<request><name>Connect</name>"; nocase; http_client_body; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011752; classtype:policy-violation; sid:2011752; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011752
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request Connect"; flow:to_server,established; content:"POST"; http_method; content:"/online_game/request.php"; http_uri; content:"User-Agent|3a| GameBox"; http_header; content:"<request><name>Connect</name>"; nocase; http_client_body; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011752; classtype:policy-violation; sid:2011752; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TrackMania Request Connect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011752

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request Disconnect"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>Disconnect</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011753; classtype:policy-violation; sid:2011753; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011753
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request Disconnect"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>Disconnect</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011753; classtype:policy-violation; sid:2011753; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request Disconnect** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011753

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetOnlineProfile"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetOnlineProfile</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011754; classtype:policy-violation; sid:2011754; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011754
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetOnlineProfile"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetOnlineProfile</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011754; classtype:policy-violation; sid:2011754; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request GetOnlineProfile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011754

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetBuddies"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetBuddies</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011755; classtype:policy-violation; sid:2011755; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011755
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request GetBuddies"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>GetBuddies</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011755; classtype:policy-violation; sid:2011755; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request GetBuddies** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011755

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request SearchNew"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>SearchNew</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011756; classtype:policy-violation; sid:2011756; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011756
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request SearchNew"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>SearchNew</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011756; classtype:policy-violation; sid:2011756; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request SearchNew** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011756

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request LiveUpdate"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>LiveUpdate</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011757; classtype:policy-violation; sid:2011757; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2011757
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET GAMES TrackMania Request LiveUpdate"; flow:to_server,established; content:"POST"; offset:0; depth:4; uricontent:"/online_game/request.php"; content:"|0d 0a|User-Agent|3a| GameBox"; content:"<request><name>LiveUpdate</name>"; nocase; reference:url,www.trackmania.com; reference:url,doc.emergingthreats.net/2011757; classtype:policy-violation; sid:2011757; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TrackMania Request LiveUpdate** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.trackmania.com|url,doc.emergingthreats.net/2011757

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 3 The Frozen throne login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PX3W"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002108; classtype:policy-violation; sid:2002108; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002108
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:"ET GAMES Battle.net Warcraft 3 The Frozen throne login"; flow:established,to_server; content:"|FF 50|"; depth:2; content:"PX3W"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002108; classtype:policy-violation; sid:2002108; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net Warcraft 3 The Frozen throne login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002108

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net failed account login (OLS) wrong password"; flow:established,from_server; content:"|FF 3A 08 00 02 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002115; classtype:policy-violation; sid:2002115; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002115
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net failed account login (OLS) wrong password"; flow:established,from_server; content:"|FF 3A 08 00 02 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002115; classtype:policy-violation; sid:2002115; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net failed account login (OLS) wrong password** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002115

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net failed account login (NLS) wrong password"; flow:established,from_server; content:"|FF 54 1C 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002116; classtype:policy-violation; sid:2002116; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002116
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET any (msg:"ET GAMES Battle.net failed account login (NLS) wrong password"; flow:established,from_server; content:"|FF 54 1C 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002116; classtype:policy-violation; sid:2002116; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net failed account login (NLS) wrong password** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002116

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Login Part 2"; flow:established; content:"|f0 be 05 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011738; classtype:policy-violation; sid:2011738; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011738
`#alert tcp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:"ET GAMES TeamSpeak2 Standard/Login Part 2"; flow:established; content:"|f0 be 05 00|"; depth:4; reference:url,teamspeak.com; reference:url,doc.emergingthreats.net/2011738; classtype:policy-violation; sid:2011738; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **TeamSpeak2 Standard/Login Part 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,teamspeak.com|url,doc.emergingthreats.net/2011738

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Second Life setup download"; flow:established,to_server; content:"/Second_Life_Setup.exe"; http_uri; reference:url,en.wikifur.com/wiki/Second_Life; reference:url,wiki.secondlife.com/wiki/Furry; classtype:policy-violation; sid:2013910; rev:3; metadata:created_at 2011_11_10, updated_at 2020_04_20;)

# 2013910
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Second Life setup download"; flow:established,to_server; content:"/Second_Life_Setup.exe"; http_uri; reference:url,en.wikifur.com/wiki/Second_Life; reference:url,wiki.secondlife.com/wiki/Furry; classtype:policy-violation; sid:2013910; rev:3; metadata:created_at 2011_11_10, updated_at 2020_04_20;)
` 

Name : **Second Life setup download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,en.wikifur.com/wiki/Second_Life|url,wiki.secondlife.com/wiki/Furry

CVE reference : Not defined

Creation date : 2011-11-10

Last modified date : 2020-04-20

Rev version : 4

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Nintendo Wii User-Agent"; flow:established,to_server; content:"(Nintendo Wii"; http_header; reference:url,www.useragentstring.com/pages/Opera/; classtype:policy-violation; sid:2014718; rev:3; metadata:created_at 2012_05_07, updated_at 2012_05_07;)

# 2014718
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Nintendo Wii User-Agent"; flow:established,to_server; content:"(Nintendo Wii"; http_header; reference:url,www.useragentstring.com/pages/Opera/; classtype:policy-violation; sid:2014718; rev:3; metadata:created_at 2012_05_07, updated_at 2012_05_07;)
` 

Name : **Nintendo Wii User-Agent** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.useragentstring.com/pages/Opera/

CVE reference : Not defined

Creation date : 2012-05-07

Last modified date : 2012-05-07

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET 7787 (msg:"GPL GAMES Unreal Tournament secure overflow attempt"; content:"|5C|secure|5C|"; nocase; pcre:"/\x5csecure\x5c[^\x00]{50}/smi"; reference:bugtraq,10570; reference:cve,2004-0608; classtype:misc-attack; sid:2103080; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2103080
`#alert udp $EXTERNAL_NET any -> $HOME_NET 7787 (msg:"GPL GAMES Unreal Tournament secure overflow attempt"; content:"|5C|secure|5C|"; nocase; pcre:"/\x5csecure\x5c[^\x00]{50}/smi"; reference:bugtraq,10570; reference:cve,2004-0608; classtype:misc-attack; sid:2103080; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Unreal Tournament secure overflow attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : bugtraq,10570|cve,2004-0608

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Blizzard Downloader Client User-Agent (Blizzard Downloader 2.x)"; flow:to_server,established; content:"Blizzard"; http_user_agent; depth:8; reference:url,www.worldofwarcraft.com/info/faq/blizzarddownloader.html; reference:url,doc.emergingthreats.net/2011708; classtype:policy-violation; sid:2011708; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011708
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Blizzard Downloader Client User-Agent (Blizzard Downloader 2.x)"; flow:to_server,established; content:"Blizzard"; http_user_agent; depth:8; reference:url,www.worldofwarcraft.com/info/faq/blizzarddownloader.html; reference:url,doc.emergingthreats.net/2011708; classtype:policy-violation; sid:2011708; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Blizzard Downloader Client User-Agent (Blizzard Downloader 2.x)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.worldofwarcraft.com/info/faq/blizzarddownloader.html|url,doc.emergingthreats.net/2011708

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> $HOME_NET 27901 (msg:"ET GAMES Alien Arena 7.30 Remote Code Execution Attempt"; content:"print|0A 5C|"; isdataat:257,relative; pcre:"/\x5C[^\x5C\x00]{257}/"; reference:url,www.packetstormsecurity.org/0910-advisories/alienarena-exec.txt; reference:url,doc.emergingthreats.net/2010156; classtype:misc-attack; sid:2010156; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2010156
`#alert udp any any -> $HOME_NET 27901 (msg:"ET GAMES Alien Arena 7.30 Remote Code Execution Attempt"; content:"print|0A 5C|"; isdataat:257,relative; pcre:"/\x5C[^\x5C\x00]{257}/"; reference:url,www.packetstormsecurity.org/0910-advisories/alienarena-exec.txt; reference:url,doc.emergingthreats.net/2010156; classtype:misc-attack; sid:2010156; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Alien Arena 7.30 Remote Code Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-attack

URL reference : url,www.packetstormsecurity.org/0910-advisories/alienarena-exec.txt|url,doc.emergingthreats.net/2010156

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET GAMES PunkBuster Server webkey Buffer Overflow"; flow:established,to_server; content:"/pbsvweb"; http_uri; nocase; content:"webkey="; nocase; isdataat:500,relative; content:!"|0A|"; within:500; content:!"&"; within:500; reference:url,aluigi.altervista.org/adv/pbwebbof-adv.txt; reference:url,doc.emergingthreats.net/2002947; classtype:attempted-admin; sid:2002947; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002947
`#alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET GAMES PunkBuster Server webkey Buffer Overflow"; flow:established,to_server; content:"/pbsvweb"; http_uri; nocase; content:"webkey="; nocase; isdataat:500,relative; content:!"|0A|"; within:500; content:!"&"; within:500; reference:url,aluigi.altervista.org/adv/pbwebbof-adv.txt; reference:url,doc.emergingthreats.net/2002947; classtype:attempted-admin; sid:2002947; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **PunkBuster Server webkey Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-admin

URL reference : url,aluigi.altervista.org/adv/pbwebbof-adv.txt|url,doc.emergingthreats.net/2002947

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 25565 -> $HOME_NET any (msg:"ET GAMES MINECRAFT Server response inbound"; flow:established,from_server; content:"|7B 22|"; depth:10; classtype:policy-violation; sid:2021701; rev:1; metadata:created_at 2015_08_21, updated_at 2015_08_21;)

# 2021701
`alert tcp $EXTERNAL_NET 25565 -> $HOME_NET any (msg:"ET GAMES MINECRAFT Server response inbound"; flow:established,from_server; content:"|7B 22|"; depth:10; classtype:policy-violation; sid:2021701; rev:1; metadata:created_at 2015_08_21, updated_at 2015_08_21;)
` 

Name : **MINECRAFT Server response inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-08-21

Last modified date : 2015-08-21

Rev version : 1

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET 25565 -> $EXTERNAL_NET any (msg:"ET GAMES MINECRAFT Server response outbound"; flow:established,from_server; content:"|7B 22|"; depth:10; classtype:policy-violation; sid:2021702; rev:1; metadata:created_at 2015_08_21, updated_at 2015_08_21;)

# 2021702
`alert tcp $HOME_NET 25565 -> $EXTERNAL_NET any (msg:"ET GAMES MINECRAFT Server response outbound"; flow:established,from_server; content:"|7B 22|"; depth:10; classtype:policy-violation; sid:2021702; rev:1; metadata:created_at 2015_08_21, updated_at 2015_08_21;)
` 

Name : **MINECRAFT Server response outbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2015-08-21

Last modified date : 2015-08-21

Rev version : 1

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET !443 (msg:"ET GAMES Battle.net connection reset (possible IP-Ban)"; flow:to_client; flags:R,12; reference:url,doc.emergingthreats.net/bin/view/Main/2002117; classtype:policy-violation; sid:2002117; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002117
`#alert tcp $EXTERNAL_NET 6112 -> $HOME_NET !443 (msg:"ET GAMES Battle.net connection reset (possible IP-Ban)"; flow:to_client; flags:R,12; reference:url,doc.emergingthreats.net/bin/view/Main/2002117; classtype:policy-violation; sid:2002117; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Battle.net connection reset (possible IP-Ban)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002117

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Blizzard Web Downloader Install Detected"; flow: established,to_server; content: "Blizzard Web Client"; nocase; depth:19; http_user_agent; classtype:policy-violation; sid:2012170; rev:3; metadata:created_at 2011_01_10, updated_at 2011_01_10;)

# 2012170
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET GAMES Blizzard Web Downloader Install Detected"; flow: established,to_server; content: "Blizzard Web Client"; nocase; depth:19; http_user_agent; classtype:policy-violation; sid:2012170; rev:3; metadata:created_at 2011_01_10, updated_at 2011_01_10;)
` 

Name : **Blizzard Web Downloader Install Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-01-10

Last modified date : 2011-01-10

Rev version : 3

Category : GAMES

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET GAMES Wolfteam HileYapak Server Response"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Temizleme Yapildi HileYapak"; depth:27; fast_pattern; http_content_type; content:"text/plain"; metadata: former_category GAMES; reference:md5,85cf4df17fcf04286fcbbdf9fbe11077; classtype:policy-violation; sid:2027417; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_05_31, performance_impact Low, updated_at 2020_02_19;)

# 2027417
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET GAMES Wolfteam HileYapak Server Response"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"Temizleme Yapildi HileYapak"; depth:27; fast_pattern; http_content_type; content:"text/plain"; metadata: former_category GAMES; reference:md5,85cf4df17fcf04286fcbbdf9fbe11077; classtype:policy-violation; sid:2027417; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2019_05_31, performance_impact Low, updated_at 2020_02_19;)
` 

Name : **Wolfteam HileYapak Server Response** 

Attack target : Client_Endpoint

Description : Wolfteam is a multiplayer FPS - this signature fires on traffic related to HileYapak, which appears to be some sort of cheat-addon to the game

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : policy-violation

URL reference : md5,85cf4df17fcf04286fcbbdf9fbe11077

CVE reference : Not defined

Creation date : 2019-05-31

Last modified date : 2020-02-19

Rev version : 3

Category : GAMES

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET GAMES Growtopia Hack - WrongGrow CnC Activity"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"|20|HeySurfer#1234"; fast_pattern; metadata: former_category GAMES; reference:md5,b76a144f412b680e6a04ee4f4fbcf000; classtype:bad-unknown; sid:2029784; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_01, updated_at 2020_04_01;)

# 2029784
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET GAMES Growtopia Hack - WrongGrow CnC Activity"; flow:established,to_client; content:"200"; http_stat_code; file_data; content:"|20|HeySurfer#1234"; fast_pattern; metadata: former_category GAMES; reference:md5,b76a144f412b680e6a04ee4f4fbcf000; classtype:bad-unknown; sid:2029784; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Informational, created_at 2020_04_01, updated_at 2020_04_01;)
` 

Name : **Growtopia Hack - WrongGrow CnC Activity** 

Attack target : Client_Endpoint

Description : Not defined

Tags : Not defined

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : bad-unknown

URL reference : md5,b76a144f412b680e6a04ee4f4fbcf000

CVE reference : Not defined

Creation date : 2020-04-01

Last modified date : 2020-04-01

Rev version : 2

Category : GAMES

Severity : Informational

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



