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



#alert tcp any any -> any any (msg:"ET SHELLCODE Bindshell2 Decoder Shellcode"; flow:established; content:"|53 53 53 53 53 43 53 43 53 FF D0 66 68|"; content:"|66 53 89 E1 95 68 A4 1A|"; distance:0; reference:url,doc.emergingthreats.net/2009246; classtype:shellcode-detect; sid:2009246; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009246
`#alert tcp any any -> any any (msg:"ET SHELLCODE Bindshell2 Decoder Shellcode"; flow:established; content:"|53 53 53 53 53 43 53 43 53 FF D0 66 68|"; content:"|66 53 89 E1 95 68 A4 1A|"; distance:0; reference:url,doc.emergingthreats.net/2009246; classtype:shellcode-detect; sid:2009246; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bindshell2 Decoder Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009246

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp any any -> any any (msg:"ET SHELLCODE Bindshell2 Decoder Shellcode (UDP)"; content:"|53 53 53 53 53 43 53 43 53 FF D0 66 68|"; content:"|66 53 89 E1 95 68 A4 1A|"; distance:0; reference:url,doc.emergingthreats.net/2009285; classtype:shellcode-detect; sid:2009285; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009285
`alert udp any any -> any any (msg:"ET SHELLCODE Bindshell2 Decoder Shellcode (UDP)"; content:"|53 53 53 53 53 43 53 43 53 FF D0 66 68|"; content:"|66 53 89 E1 95 68 A4 1A|"; distance:0; reference:url,doc.emergingthreats.net/2009285; classtype:shellcode-detect; sid:2009285; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bindshell2 Decoder Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009285

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any any (msg:"ET SHELLCODE Rothenburg Shellcode"; flow:established; content:"|D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance:0; reference:url,doc.emergingthreats.net/2009247; classtype:shellcode-detect; sid:2009247; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009247
`alert tcp any any -> any any (msg:"ET SHELLCODE Rothenburg Shellcode"; flow:established; content:"|D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance:0; reference:url,doc.emergingthreats.net/2009247; classtype:shellcode-detect; sid:2009247; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rothenburg Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009247

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Rothenburg Shellcode (UDP)"; content:"|D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance:0; reference:url,doc.emergingthreats.net/2009284; classtype:shellcode-detect; sid:2009284; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009284
`#alert udp any any -> any any (msg:"ET SHELLCODE Rothenburg Shellcode (UDP)"; content:"|D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance:0; reference:url,doc.emergingthreats.net/2009284; classtype:shellcode-detect; sid:2009284; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Rothenburg Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009284

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Lindau (linkbot) xor Decoder Shellcode"; flow:established; content:"|EB 15 B9|"; content:"|81 F1|"; distance:0; content:"|80 74 31 FF|"; distance:0; content:"|E2 F9 EB 05 E8 E6 FF FF FF|"; reference:url,doc.emergingthreats.net/2009248; classtype:shellcode-detect; sid:2009248; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009248
`#alert tcp any any -> any any (msg:"ET SHELLCODE Lindau (linkbot) xor Decoder Shellcode"; flow:established; content:"|EB 15 B9|"; content:"|81 F1|"; distance:0; content:"|80 74 31 FF|"; distance:0; content:"|E2 F9 EB 05 E8 E6 FF FF FF|"; reference:url,doc.emergingthreats.net/2009248; classtype:shellcode-detect; sid:2009248; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Lindau (linkbot) xor Decoder Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009248

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Lindau (linkbot) xor Decoder Shellcode (UDP)"; content:"|EB 15 B9|"; content:"|81 F1|"; distance:0; content:"|80 74 31 FF|"; distance:0; content:"|E2 F9 EB 05 E8 E6 FF FF FF|"; reference:url,doc.emergingthreats.net/2009283; classtype:shellcode-detect; sid:2009283; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009283
`#alert udp any any -> any any (msg:"ET SHELLCODE Lindau (linkbot) xor Decoder Shellcode (UDP)"; content:"|EB 15 B9|"; content:"|81 F1|"; distance:0; content:"|80 74 31 FF|"; distance:0; content:"|E2 F9 EB 05 E8 E6 FF FF FF|"; reference:url,doc.emergingthreats.net/2009283; classtype:shellcode-detect; sid:2009283; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Lindau (linkbot) xor Decoder Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009283

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Adenau Shellcode"; flow:established; content:"|eb 19 5e 31 c9 81 e9|"; content:"|81 36|"; distance:0; content:"|81 ee fc ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009249; classtype:shellcode-detect; sid:2009249; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009249
`#alert tcp any any -> any any (msg:"ET SHELLCODE Adenau Shellcode"; flow:established; content:"|eb 19 5e 31 c9 81 e9|"; content:"|81 36|"; distance:0; content:"|81 ee fc ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009249; classtype:shellcode-detect; sid:2009249; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Adenau Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009249

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Adenau Shellcode (UDP)"; content:"|eb 19 5e 31 c9 81 e9|"; content:"|81 36|"; distance:0; content:"|81 ee fc ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009282; classtype:shellcode-detect; sid:2009282; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009282
`#alert udp any any -> any any (msg:"ET SHELLCODE Adenau Shellcode (UDP)"; content:"|eb 19 5e 31 c9 81 e9|"; content:"|81 36|"; distance:0; content:"|81 ee fc ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009282; classtype:shellcode-detect; sid:2009282; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Adenau Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009282

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Mainz/Bielefeld Shellcode"; flow:established; content:"|33 c9 66 b9|"; content:"|80 34|"; distance:0; content:"|eb 05 e8 eb ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009250; classtype:shellcode-detect; sid:2009250; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009250
`#alert tcp any any -> any any (msg:"ET SHELLCODE Mainz/Bielefeld Shellcode"; flow:established; content:"|33 c9 66 b9|"; content:"|80 34|"; distance:0; content:"|eb 05 e8 eb ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009250; classtype:shellcode-detect; sid:2009250; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Mainz/Bielefeld Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009250

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Mainz/Bielefeld Shellcode (UDP)"; content:"|33 c9 66 b9|"; content:"|80 34|"; distance:0; content:"|eb 05 e8 eb ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009281; classtype:shellcode-detect; sid:2009281; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009281
`#alert udp any any -> any any (msg:"ET SHELLCODE Mainz/Bielefeld Shellcode (UDP)"; content:"|33 c9 66 b9|"; content:"|80 34|"; distance:0; content:"|eb 05 e8 eb ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009281; classtype:shellcode-detect; sid:2009281; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Mainz/Bielefeld Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009281

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Wuerzburg Shellcode"; flow:established; content:"|eb 27|"; content:"|5d 33 c9 66 b9|"; distance:0; content:"|8d 75 05 8b fe 8a 06 3c|"; distance:0; content:"|75 05 46 8a 06|"; distance:0; content:"|88 07 47 e2 ed eb 0a e8 da ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009251; classtype:shellcode-detect; sid:2009251; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009251
`#alert tcp any any -> any any (msg:"ET SHELLCODE Wuerzburg Shellcode"; flow:established; content:"|eb 27|"; content:"|5d 33 c9 66 b9|"; distance:0; content:"|8d 75 05 8b fe 8a 06 3c|"; distance:0; content:"|75 05 46 8a 06|"; distance:0; content:"|88 07 47 e2 ed eb 0a e8 da ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009251; classtype:shellcode-detect; sid:2009251; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Wuerzburg Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009251

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Wuerzburg Shellcode (UDP)"; content:"|eb 27|"; content:"|5d 33 c9 66 b9|"; distance:0; content:"|8d 75 05 8b fe 8a 06 3c|"; distance:0; content:"|75 05 46 8a 06|"; distance:0; content:"|88 07 47 e2 ed eb 0a e8 da ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009280; classtype:shellcode-detect; sid:2009280; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009280
`#alert udp any any -> any any (msg:"ET SHELLCODE Wuerzburg Shellcode (UDP)"; content:"|eb 27|"; content:"|5d 33 c9 66 b9|"; distance:0; content:"|8d 75 05 8b fe 8a 06 3c|"; distance:0; content:"|75 05 46 8a 06|"; distance:0; content:"|88 07 47 e2 ed eb 0a e8 da ff ff ff|"; distance:0; reference:url,doc.emergingthreats.net/2009280; classtype:shellcode-detect; sid:2009280; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Wuerzburg Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009280

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Schauenburg Shellcode"; flow:established; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009252; classtype:shellcode-detect; sid:2009252; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009252
`#alert tcp any any -> any any (msg:"ET SHELLCODE Schauenburg Shellcode"; flow:established; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009252; classtype:shellcode-detect; sid:2009252; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Schauenburg Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009252

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Schauenburg Shellcode (UDP)"; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009279; classtype:shellcode-detect; sid:2009279; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009279
`#alert udp any any -> any any (msg:"ET SHELLCODE Schauenburg Shellcode (UDP)"; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009279; classtype:shellcode-detect; sid:2009279; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Schauenburg Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009279

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Koeln Shellcode"; flow:established; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009253; classtype:shellcode-detect; sid:2009253; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009253
`#alert tcp any any -> any any (msg:"ET SHELLCODE Koeln Shellcode"; flow:established; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009253; classtype:shellcode-detect; sid:2009253; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Koeln Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009253

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Koeln Shellcode (UDP)"; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009278; classtype:shellcode-detect; sid:2009278; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009278
`#alert udp any any -> any any (msg:"ET SHELLCODE Koeln Shellcode (UDP)"; content:"|eb 0f 8b 34 24 33 c9 80 c1|"; content:"|80 36|"; distance:0; content:"|46 e2 fa c3 e8 ec|"; distance:0; reference:url,doc.emergingthreats.net/2009278; classtype:shellcode-detect; sid:2009278; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Koeln Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009278

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Lichtenfels Shellcode"; flow:established; content:"|01 fc ff ff 83 e4 fc 8b ec 33 c9 66 b9|"; content:"|80 30|"; distance:0; content:"|40 e2 fA|"; distance:0; reference:url,doc.emergingthreats.net/2009254; classtype:shellcode-detect; sid:2009254; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009254
`#alert tcp any any -> any any (msg:"ET SHELLCODE Lichtenfels Shellcode"; flow:established; content:"|01 fc ff ff 83 e4 fc 8b ec 33 c9 66 b9|"; content:"|80 30|"; distance:0; content:"|40 e2 fA|"; distance:0; reference:url,doc.emergingthreats.net/2009254; classtype:shellcode-detect; sid:2009254; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Lichtenfels Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009254

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Lichtenfels Shellcode (UDP)"; content:"|01 fc ff ff 83 e4 fc 8b ec 33 c9 66 b9|"; content:"|80 30|"; distance:0; content:"|40 e2 fA|"; distance:0; reference:url,doc.emergingthreats.net/2009277; classtype:shellcode-detect; sid:2009277; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009277
`#alert udp any any -> any any (msg:"ET SHELLCODE Lichtenfels Shellcode (UDP)"; content:"|01 fc ff ff 83 e4 fc 8b ec 33 c9 66 b9|"; content:"|80 30|"; distance:0; content:"|40 e2 fA|"; distance:0; reference:url,doc.emergingthreats.net/2009277; classtype:shellcode-detect; sid:2009277; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Lichtenfels Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009277

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Mannheim Shellcode"; flow:established; content:"|80 73 0e|"; content:"|43 e2|"; distance:0; content:"|73 73 73|"; distance:0; content:"|81 86 8c 81|"; distance:0; reference:url,doc.emergingthreats.net/2009255; classtype:shellcode-detect; sid:2009255; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009255
`#alert tcp any any -> any any (msg:"ET SHELLCODE Mannheim Shellcode"; flow:established; content:"|80 73 0e|"; content:"|43 e2|"; distance:0; content:"|73 73 73|"; distance:0; content:"|81 86 8c 81|"; distance:0; reference:url,doc.emergingthreats.net/2009255; classtype:shellcode-detect; sid:2009255; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Mannheim Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009255

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Mannheim Shellcode (UDP)"; content:"|80 73 0e|"; content:"|43 e2|"; distance:0; content:"|73 73 73|"; distance:0; content:"|81 86 8c 81|"; distance:0; reference:url,doc.emergingthreats.net/2009276; classtype:shellcode-detect; sid:2009276; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009276
`#alert udp any any -> any any (msg:"ET SHELLCODE Mannheim Shellcode (UDP)"; content:"|80 73 0e|"; content:"|43 e2|"; distance:0; content:"|73 73 73|"; distance:0; content:"|81 86 8c 81|"; distance:0; reference:url,doc.emergingthreats.net/2009276; classtype:shellcode-detect; sid:2009276; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Mannheim Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009276

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Berlin Shellcode"; flow:established; content:"|31 c9 b1 fc 80 73 0c|"; content:"|43 e2 8b 9f|"; distance:0; reference:url,doc.emergingthreats.net/2009256; classtype:shellcode-detect; sid:2009256; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009256
`#alert tcp any any -> any any (msg:"ET SHELLCODE Berlin Shellcode"; flow:established; content:"|31 c9 b1 fc 80 73 0c|"; content:"|43 e2 8b 9f|"; distance:0; reference:url,doc.emergingthreats.net/2009256; classtype:shellcode-detect; sid:2009256; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Berlin Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009256

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Berlin Shellcode (UDP)"; content:"|31 c9 b1 fc 80 73 0c|"; content:"|43 e2 8b 9f|"; distance:0; reference:url,doc.emergingthreats.net/2009275; classtype:shellcode-detect; sid:2009275; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009275
`#alert udp any any -> any any (msg:"ET SHELLCODE Berlin Shellcode (UDP)"; content:"|31 c9 b1 fc 80 73 0c|"; content:"|43 e2 8b 9f|"; distance:0; reference:url,doc.emergingthreats.net/2009275; classtype:shellcode-detect; sid:2009275; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Berlin Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009275

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Leimbach Shellcode"; flow:established; content:"|5b 31 c9 b1|"; content:"|80 73|"; distance:0; content:"|43 e2|"; distance:0; reference:url,doc.emergingthreats.net/2009257; classtype:shellcode-detect; sid:2009257; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009257
`#alert tcp any any -> any any (msg:"ET SHELLCODE Leimbach Shellcode"; flow:established; content:"|5b 31 c9 b1|"; content:"|80 73|"; distance:0; content:"|43 e2|"; distance:0; reference:url,doc.emergingthreats.net/2009257; classtype:shellcode-detect; sid:2009257; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Leimbach Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009257

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Leimbach Shellcode (UDP)"; content:"|5b 31 c9 b1|"; content:"|80 73|"; distance:0; content:"|43 e2|"; distance:0; reference:url,doc.emergingthreats.net/2009274; classtype:shellcode-detect; sid:2009274; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009274
`#alert udp any any -> any any (msg:"ET SHELLCODE Leimbach Shellcode (UDP)"; content:"|5b 31 c9 b1|"; content:"|80 73|"; distance:0; content:"|43 e2|"; distance:0; reference:url,doc.emergingthreats.net/2009274; classtype:shellcode-detect; sid:2009274; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Leimbach Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009274

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Aachen Shellcode"; flow:established; content:"|8b 45 04 35|"; content:"|89 45 04 66 8b 45 02 66 35|"; distance:0; content:"|66 89 45 02|"; distance:0; reference:url,doc.emergingthreats.net/2009258; classtype:shellcode-detect; sid:2009258; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009258
`#alert tcp any any -> any any (msg:"ET SHELLCODE Aachen Shellcode"; flow:established; content:"|8b 45 04 35|"; content:"|89 45 04 66 8b 45 02 66 35|"; distance:0; content:"|66 89 45 02|"; distance:0; reference:url,doc.emergingthreats.net/2009258; classtype:shellcode-detect; sid:2009258; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Aachen Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009258

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Aachen Shellcode (UDP)"; content:"|8b 45 04 35|"; content:"|89 45 04 66 8b 45 02 66 35|"; distance:0; content:"|66 89 45 02|"; distance:0; reference:url,doc.emergingthreats.net/2009273; classtype:shellcode-detect; sid:2009273; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009273
`#alert udp any any -> any any (msg:"ET SHELLCODE Aachen Shellcode (UDP)"; content:"|8b 45 04 35|"; content:"|89 45 04 66 8b 45 02 66 35|"; distance:0; content:"|66 89 45 02|"; distance:0; reference:url,doc.emergingthreats.net/2009273; classtype:shellcode-detect; sid:2009273; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Aachen Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009273

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Furth Shellcode"; flow:established; content:"|31 c9 66 b9|"; content:"|80 73|"; distance:0; content:"|43 e2 1f|"; distance:0; reference:url,doc.emergingthreats.net/2009259; classtype:shellcode-detect; sid:2009259; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009259
`#alert tcp any any -> any any (msg:"ET SHELLCODE Furth Shellcode"; flow:established; content:"|31 c9 66 b9|"; content:"|80 73|"; distance:0; content:"|43 e2 1f|"; distance:0; reference:url,doc.emergingthreats.net/2009259; classtype:shellcode-detect; sid:2009259; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Furth Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009259

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Furth Shellcode (UDP)"; content:"|31 c9 66 b9|"; content:"|80 73|"; distance:0; content:"|43 e2 1f|"; distance:0; reference:url,doc.emergingthreats.net/2009272; classtype:shellcode-detect; sid:2009272; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009272
`#alert udp any any -> any any (msg:"ET SHELLCODE Furth Shellcode (UDP)"; content:"|31 c9 66 b9|"; content:"|80 73|"; distance:0; content:"|43 e2 1f|"; distance:0; reference:url,doc.emergingthreats.net/2009272; classtype:shellcode-detect; sid:2009272; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Furth Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009272

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Langenfeld Shellcode"; flow:established; content:"|eb 0f 5b 33 c9 66 b9|"; content:"|80 33|"; distance:0; content:"|43 e2 fa eb|"; distance:0; reference:url,doc.emergingthreats.net/2009260; classtype:shellcode-detect; sid:2009260; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009260
`#alert tcp any any -> any any (msg:"ET SHELLCODE Langenfeld Shellcode"; flow:established; content:"|eb 0f 5b 33 c9 66 b9|"; content:"|80 33|"; distance:0; content:"|43 e2 fa eb|"; distance:0; reference:url,doc.emergingthreats.net/2009260; classtype:shellcode-detect; sid:2009260; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Langenfeld Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009260

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Langenfeld Shellcode (UDP)"; content:"|eb 0f 5b 33 c9 66 b9|"; content:"|80 33|"; distance:0; content:"|43 e2 fa eb|"; distance:0; reference:url,doc.emergingthreats.net/2009271; classtype:shellcode-detect; sid:2009271; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009271
`#alert udp any any -> any any (msg:"ET SHELLCODE Langenfeld Shellcode (UDP)"; content:"|eb 0f 5b 33 c9 66 b9|"; content:"|80 33|"; distance:0; content:"|43 e2 fa eb|"; distance:0; reference:url,doc.emergingthreats.net/2009271; classtype:shellcode-detect; sid:2009271; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Langenfeld Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009271

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Bonn Shellcode"; flow:established; content:"|31 c9 81 e9|"; content:"|83 eb|"; distance:0; content:"|80 73|"; distance:0; content:"|43 e2 f9|"; distance:0; reference:url,doc.emergingthreats.net/2009261; classtype:shellcode-detect; sid:2009261; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009261
`#alert tcp any any -> any any (msg:"ET SHELLCODE Bonn Shellcode"; flow:established; content:"|31 c9 81 e9|"; content:"|83 eb|"; distance:0; content:"|80 73|"; distance:0; content:"|43 e2 f9|"; distance:0; reference:url,doc.emergingthreats.net/2009261; classtype:shellcode-detect; sid:2009261; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bonn Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009261

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Bonn Shellcode (UDP)"; content:"|31 c9 81 e9|"; content:"|83 eb|"; distance:0; content:"|80 73|"; distance:0; content:"|43 e2 f9|"; distance:0; reference:url,doc.emergingthreats.net/2009270; classtype:shellcode-detect; sid:2009270; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009270
`#alert udp any any -> any any (msg:"ET SHELLCODE Bonn Shellcode (UDP)"; content:"|31 c9 81 e9|"; content:"|83 eb|"; distance:0; content:"|80 73|"; distance:0; content:"|43 e2 f9|"; distance:0; reference:url,doc.emergingthreats.net/2009270; classtype:shellcode-detect; sid:2009270; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bonn Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009270

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Siegburg Shellcode"; flow:established; content:"|31 eb 80 eb|"; content:"|58 80 30|"; distance:0; content:"|40 81 38|"; distance:0; reference:url,doc.emergingthreats.net/2009262; classtype:shellcode-detect; sid:2009262; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009262
`#alert tcp any any -> any any (msg:"ET SHELLCODE Siegburg Shellcode"; flow:established; content:"|31 eb 80 eb|"; content:"|58 80 30|"; distance:0; content:"|40 81 38|"; distance:0; reference:url,doc.emergingthreats.net/2009262; classtype:shellcode-detect; sid:2009262; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Siegburg Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009262

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Siegburg Shellcode (UDP)"; content:"|31 eb 80 eb|"; content:"|58 80 30|"; distance:0; content:"|40 81 38|"; distance:0; reference:url,doc.emergingthreats.net/2009269; classtype:shellcode-detect; sid:2009269; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009269
`#alert udp any any -> any any (msg:"ET SHELLCODE Siegburg Shellcode (UDP)"; content:"|31 eb 80 eb|"; content:"|58 80 30|"; distance:0; content:"|40 81 38|"; distance:0; reference:url,doc.emergingthreats.net/2009269; classtype:shellcode-detect; sid:2009269; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Siegburg Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009269

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Plain1 Shellcode"; flow:established; content:"|89 e1 cd|"; content:"|5b 5d 52 66 bd|"; distance:0; content:"|0f cd 09 dd 55 6a|"; distance:0; content:"|51 50|"; distance:0; reference:url,doc.emergingthreats.net/2009263; classtype:shellcode-detect; sid:2009263; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009263
`#alert tcp any any -> any any (msg:"ET SHELLCODE Plain1 Shellcode"; flow:established; content:"|89 e1 cd|"; content:"|5b 5d 52 66 bd|"; distance:0; content:"|0f cd 09 dd 55 6a|"; distance:0; content:"|51 50|"; distance:0; reference:url,doc.emergingthreats.net/2009263; classtype:shellcode-detect; sid:2009263; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Plain1 Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009263

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Plain1 Shellcode (UDP)"; content:"|89 e1 cd|"; content:"|5b 5d 52 66 bd|"; distance:0; content:"|0f cd 09 dd 55 6a|"; distance:0; content:"|51 50|"; distance:0; reference:url,doc.emergingthreats.net/2009268; classtype:shellcode-detect; sid:2009268; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009268
`#alert udp any any -> any any (msg:"ET SHELLCODE Plain1 Shellcode (UDP)"; content:"|89 e1 cd|"; content:"|5b 5d 52 66 bd|"; distance:0; content:"|0f cd 09 dd 55 6a|"; distance:0; content:"|51 50|"; distance:0; reference:url,doc.emergingthreats.net/2009268; classtype:shellcode-detect; sid:2009268; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Plain1 Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009268

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Plain2 Shellcode"; flow:established; content:"|50 50 50 50 40 50 40 50 ff 56 1c 8b d8 57 57 68 02|"; content:"|8b cc 6a|"; distance:0; content:"|51 53|"; distance:0; reference:url,doc.emergingthreats.net/2009264; classtype:shellcode-detect; sid:2009264; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009264
`#alert tcp any any -> any any (msg:"ET SHELLCODE Plain2 Shellcode"; flow:established; content:"|50 50 50 50 40 50 40 50 ff 56 1c 8b d8 57 57 68 02|"; content:"|8b cc 6a|"; distance:0; content:"|51 53|"; distance:0; reference:url,doc.emergingthreats.net/2009264; classtype:shellcode-detect; sid:2009264; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Plain2 Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009264

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Plain2 Shellcode (UDP)"; content:"|50 50 50 50 40 50 40 50 ff 56 1c 8b d8 57 57 68 02|"; content:"|8b cc 6a|"; distance:0; content:"|51 53|"; distance:0; reference:url,doc.emergingthreats.net/2009267; classtype:shellcode-detect; sid:2009267; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009267
`#alert udp any any -> any any (msg:"ET SHELLCODE Plain2 Shellcode (UDP)"; content:"|50 50 50 50 40 50 40 50 ff 56 1c 8b d8 57 57 68 02|"; content:"|8b cc 6a|"; distance:0; content:"|51 53|"; distance:0; reference:url,doc.emergingthreats.net/2009267; classtype:shellcode-detect; sid:2009267; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Plain2 Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009267

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp any any -> any any (msg:"ET SHELLCODE Bindshell1 Decoder Shellcode"; flow:established; content:"|58 99 89 E1 CD 80 96 43 52 66 68|"; content:"|66 53 89 E1 6A 66 58 50 51 56|"; distance:0; reference:url,doc.emergingthreats.net/2009265; classtype:shellcode-detect; sid:2009265; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009265
`#alert tcp any any -> any any (msg:"ET SHELLCODE Bindshell1 Decoder Shellcode"; flow:established; content:"|58 99 89 E1 CD 80 96 43 52 66 68|"; content:"|66 53 89 E1 6A 66 58 50 51 56|"; distance:0; reference:url,doc.emergingthreats.net/2009265; classtype:shellcode-detect; sid:2009265; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bindshell1 Decoder Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009265

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp any any -> any any (msg:"ET SHELLCODE Bindshell1 Decoder Shellcode (UDP)"; content:"|58 99 89 E1 CD 80 96 43 52 66 68|"; content:"|66 53 89 E1 6A 66 58 50 51 56|"; distance:0; reference:url,doc.emergingthreats.net/2009266; classtype:shellcode-detect; sid:2009266; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009266
`#alert udp any any -> any any (msg:"ET SHELLCODE Bindshell1 Decoder Shellcode (UDP)"; content:"|58 99 89 E1 CD 80 96 43 52 66 68|"; content:"|66 53 89 E1 6A 66 58 50 51 56|"; distance:0; reference:url,doc.emergingthreats.net/2009266; classtype:shellcode-detect; sid:2009266; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Bindshell1 Decoder Shellcode (UDP)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2009266

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell"; content:"|83 e9 ec d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010383; classtype:shellcode-detect; sid:2010383; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010383
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell"; content:"|83 e9 ec d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010383; classtype:shellcode-detect; sid:2010383; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010383

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 2)"; content:"|89 e1 52 42 52 42 52 6a 10 cd 80 99 93 51 53 52 6a 68 58 cd|"; reference:url,doc.emergingthreats.net/2010392; classtype:shellcode-detect; sid:2010392; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010392
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 2)"; content:"|89 e1 52 42 52 42 52 6a 10 cd 80 99 93 51 53 52 6a 68 58 cd|"; reference:url,doc.emergingthreats.net/2010392; classtype:shellcode-detect; sid:2010392; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Not Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010392

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (JmpCallAdditive Encoded 1)"; content:"|eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff|"; reference:url,doc.emergingthreats.net/2010423; classtype:shellcode-detect; sid:2010423; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010423
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (JmpCallAdditive Encoded 1)"; content:"|eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff|"; reference:url,doc.emergingthreats.net/2010423; classtype:shellcode-detect; sid:2010423; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (JmpCallAdditive Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010423

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 1)"; content:"|49 49 49 49 49 49 49 51 5a 6a|"; reference:url,doc.emergingthreats.net/2010424; classtype:shellcode-detect; sid:2010424; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010424
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 1)"; content:"|49 49 49 49 49 49 49 51 5a 6a|"; reference:url,doc.emergingthreats.net/2010424; classtype:shellcode-detect; sid:2010424; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Alpha2 Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010424

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 2)"; content:"|58 50 30 42 31 41 42 6b 42 41|"; reference:url,doc.emergingthreats.net/2010425; classtype:shellcode-detect; sid:2010425; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010425
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 2)"; content:"|58 50 30 42 31 41 42 6b 42 41|"; reference:url,doc.emergingthreats.net/2010425; classtype:shellcode-detect; sid:2010425; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Alpha2 Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010425

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 3)"; content:"|32 41 41 30 41 41 58 50 38 42 42 75|"; reference:url,doc.emergingthreats.net/2010426; classtype:shellcode-detect; sid:2010426; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010426
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Alpha2 Encoded 3)"; content:"|32 41 41 30 41 41 58 50 38 42 42 75|"; reference:url,doc.emergingthreats.net/2010426; classtype:shellcode-detect; sid:2010426; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Alpha2 Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010426

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (SPARC Encoded 1)"; content:"|20 bf ff ff 20 bf ff ff 7f ff ff ff ea 03 e0 20 aa 9d 40 11|"; reference:url,doc.emergingthreats.net/2010427; classtype:shellcode-detect; sid:2010427; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010427
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (SPARC Encoded 1)"; content:"|20 bf ff ff 20 bf ff ff 7f ff ff ff ea 03 e0 20 aa 9d 40 11|"; reference:url,doc.emergingthreats.net/2010427; classtype:shellcode-detect; sid:2010427; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (SPARC Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010427

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (SPARC Encoded 2)"; content:"|ea 23 e0 20 a2 04 40 15 81 db e0 20 12 bf ff fb 9e 03 e0 04|"; reference:url,doc.emergingthreats.net/2010428; classtype:shellcode-detect; sid:2010428; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010428
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (SPARC Encoded 2)"; content:"|ea 23 e0 20 a2 04 40 15 81 db e0 20 12 bf ff fb 9e 03 e0 04|"; reference:url,doc.emergingthreats.net/2010428; classtype:shellcode-detect; sid:2010428; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (SPARC Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010428

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 1)"; content:"|e0 23 bf f0 c0 23 bf f4 92 23 a0 10 94 10 20 10 82 10 20 68|"; reference:url,doc.emergingthreats.net/2010429; classtype:shellcode-detect; sid:2010429; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010429
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 1)"; content:"|e0 23 bf f0 c0 23 bf f4 92 23 a0 10 94 10 20 10 82 10 20 68|"; reference:url,doc.emergingthreats.net/2010429; classtype:shellcode-detect; sid:2010429; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (Not Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010429

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 2)"; content:"|91 d0 20 08 d0 03 bf f8 92 10 20 01 82 10 20 6a 91 d0 20 08|"; reference:url,doc.emergingthreats.net/2010430; classtype:shellcode-detect; sid:2010430; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010430
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 2)"; content:"|91 d0 20 08 d0 03 bf f8 92 10 20 01 82 10 20 6a 91 d0 20 08|"; reference:url,doc.emergingthreats.net/2010430; classtype:shellcode-detect; sid:2010430; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (Not Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010430

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 3)"; content:"|d0 03 bf f8 92 1a 40 09 94 12 40 09 82 10 20 1e 91 d0 20 08|"; reference:url,doc.emergingthreats.net/2010431; classtype:shellcode-detect; sid:2010431; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010431
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 3)"; content:"|d0 03 bf f8 92 1a 40 09 94 12 40 09 82 10 20 1e 91 d0 20 08|"; reference:url,doc.emergingthreats.net/2010431; classtype:shellcode-detect; sid:2010431; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (Not Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010431

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 4)"; content:"|23 0b dc da 90 23 a0 10 92 23 a0 08 e0 3b bf f0 d0 23 bf f8|"; reference:url,doc.emergingthreats.net/2010432; classtype:shellcode-detect; sid:2010432; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010432
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Bind shell (Not Encoded 4)"; content:"|23 0b dc da 90 23 a0 10 92 23 a0 08 e0 3b bf f0 d0 23 bf f8|"; reference:url,doc.emergingthreats.net/2010432; classtype:shellcode-detect; sid:2010432; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Bind shell (Not Encoded 4)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010432

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 1)"; content:"|9c 2b a0 07 94 1a c0 0b 92 10 20 01 90 10 20 02 82 10 20 61|"; reference:url,doc.emergingthreats.net/2010433; classtype:shellcode-detect; sid:2010433; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010433
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 1)"; content:"|9c 2b a0 07 94 1a c0 0b 92 10 20 01 90 10 20 02 82 10 20 61|"; reference:url,doc.emergingthreats.net/2010433; classtype:shellcode-detect; sid:2010433; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Reverse shell (Not Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010433

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 2)"; content:"|91 d0 20 08 d0 23 bf f8 92 10 20 03 92 a2 60 01 82 10 20 5a|"; reference:url,doc.emergingthreats.net/2010434; classtype:shellcode-detect; sid:2010434; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010434
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 2)"; content:"|91 d0 20 08 d0 23 bf f8 92 10 20 03 92 a2 60 01 82 10 20 5a|"; reference:url,doc.emergingthreats.net/2010434; classtype:shellcode-detect; sid:2010434; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Reverse shell (Not Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010434

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 3)"; content:"|91 d0 20 08 12 bf ff fd d0 03 bf f8 21 3f c0|"; reference:url,doc.emergingthreats.net/2010437; classtype:shellcode-detect; sid:2010437; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010437
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (Not Encoded 3)"; content:"|91 d0 20 08 12 bf ff fd d0 03 bf f8 21 3f c0|"; reference:url,doc.emergingthreats.net/2010437; classtype:shellcode-detect; sid:2010437; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Reverse shell (Not Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010437

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 1)"; content:"|20 bf ff ff 20 bf ff ff 7f ff ff ff ea 03 e0 20 aa 9d 40 11|"; reference:url,doc.emergingthreats.net/2010435; classtype:shellcode-detect; sid:2010435; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010435
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 1)"; content:"|20 bf ff ff 20 bf ff ff 7f ff ff ff ea 03 e0 20 aa 9d 40 11|"; reference:url,doc.emergingthreats.net/2010435; classtype:shellcode-detect; sid:2010435; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010435

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 2)"; content:"|ea 23 e0 20 a2 04 40 15 81 db e0 20 12 bf ff fb 9e 03 e0 04|"; reference:url,doc.emergingthreats.net/2010436; classtype:shellcode-detect; sid:2010436; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010436
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 2)"; content:"|ea 23 e0 20 a2 04 40 15 81 db e0 20 12 bf ff fb 9e 03 e0 04|"; reference:url,doc.emergingthreats.net/2010436; classtype:shellcode-detect; sid:2010436; rev:2; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD SPARC Reverse shell (SPARC Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010436

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 PexFnstenvMov/Sub Encoder"; flow:established; content:"|D9 EE D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance: 4; within: 5; reference:url,doc.emergingthreats.net/bin/view/Main/2002903; classtype:shellcode-detect; sid:2002903; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002903
`#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 PexFnstenvMov/Sub Encoder"; flow:established; content:"|D9 EE D9 74 24 F4 5B 81 73 13|"; content:"|83 EB FC E2 F4|"; distance: 4; within: 5; reference:url,doc.emergingthreats.net/bin/view/Main/2002903; classtype:shellcode-detect; sid:2002903; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 PexFnstenvMov/Sub Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002903

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 Alpha2 GetEIPs Encoder"; flow:established; content:"|EB 03 59 EB 05 E8 F8 FF FF FF|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002904; classtype:shellcode-detect; sid:2002904; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002904
`#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 Alpha2 GetEIPs Encoder"; flow:established; content:"|EB 03 59 EB 05 E8 F8 FF FF FF|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002904; classtype:shellcode-detect; sid:2002904; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 Alpha2 GetEIPs Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002904

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 Countdown Encoder"; flow:established; content:"|E8 FF FF FF FF C1 5E 30 4C 0E 07 E2 FA|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002905; classtype:shellcode-detect; sid:2002905; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002905
`#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 Countdown Encoder"; flow:established; content:"|E8 FF FF FF FF C1 5E 30 4C 0E 07 E2 FA|"; reference:url,doc.emergingthreats.net/bin/view/Main/2002905; classtype:shellcode-detect; sid:2002905; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 Countdown Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002905

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 PexAlphaNum Encoder"; flow:established; content:"VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089"; content:"JJJJJ"; distance: 2; within: 5; content:"VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM"; distance: 2; within: 55; reference:url,doc.emergingthreats.net/bin/view/Main/2002906; classtype:shellcode-detect; sid:2002906; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002906
`#alert tcp $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"ET SHELLCODE x86 PexAlphaNum Encoder"; flow:established; content:"VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089"; content:"JJJJJ"; distance: 2; within: 5; content:"VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM"; distance: 2; within: 55; reference:url,doc.emergingthreats.net/bin/view/Main/2002906; classtype:shellcode-detect; sid:2002906; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 PexAlphaNum Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002906

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE x86 PexCall Encoder"; flow:established; content:"|E8 FF FF FF FF C0 5E 81 76 0E|"; content:"|82 EE FC E2 F4|"; distance: 4; within: 5; reference:url,doc.emergingthreats.net/bin/view/Main/2002907; classtype:shellcode-detect; sid:2002907; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002907
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE x86 PexCall Encoder"; flow:established; content:"|E8 FF FF FF FF C0 5E 81 76 0E|"; content:"|82 EE FC E2 F4|"; distance: 4; within: 5; reference:url,doc.emergingthreats.net/bin/view/Main/2002907; classtype:shellcode-detect; sid:2002907; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 PexCall Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002907

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE x86 JmpCallAdditive Encoder"; flow:established; content:"|FC BB|"; content:"|EB 0C 5E 56 31 1E AD 01 C3 85 C0 75 F7 C3 E8 EF FF FF FF|"; distance: 4; within: 19; reference:url,doc.emergingthreats.net/bin/view/Main/2002908; classtype:shellcode-detect; sid:2002908; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002908
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE x86 JmpCallAdditive Encoder"; flow:established; content:"|FC BB|"; content:"|EB 0C 5E 56 31 1E AD 01 C3 85 C0 75 F7 C3 E8 EF FF FF FF|"; distance: 4; within: 19; reference:url,doc.emergingthreats.net/bin/view/Main/2002908; classtype:shellcode-detect; sid:2002908; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **x86 JmpCallAdditive Encoder** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/bin/view/Main/2002908

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-8 encoded Shellcode Detected"; flow:from_server,established; content:"%u"; nocase; isdataat:2; content:!"|0A|"; within:2; content:!"|20|"; within:2; pcre:"/(%U([0-9a-f]{2})){6}/i"; reference:url,doc.emergingthreats.net/bin/view/Main/2003173; classtype:trojan-activity; sid:2003173; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003173
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-8 encoded Shellcode Detected"; flow:from_server,established; content:"%u"; nocase; isdataat:2; content:!"|0A|"; within:2; content:!"|20|"; within:2; pcre:"/(%U([0-9a-f]{2})){6}/i"; reference:url,doc.emergingthreats.net/bin/view/Main/2003173; classtype:trojan-activity; sid:2003173; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible UTF-8 encoded Shellcode Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003173

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 encoded Shellcode Detected"; flow:from_server,established; content:"%u"; nocase; isdataat:4; content:!"|0A|"; within:4; content:!"|20|"; within:4; pcre:"/(%U([0-9a-f]{4})){6}/i"; reference:url,doc.emergingthreats.net/bin/view/Main/2003174; classtype:trojan-activity; sid:2003174; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003174
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 encoded Shellcode Detected"; flow:from_server,established; content:"%u"; nocase; isdataat:4; content:!"|0A|"; within:4; content:!"|20|"; within:4; pcre:"/(%U([0-9a-f]{4})){6}/i"; reference:url,doc.emergingthreats.net/bin/view/Main/2003174; classtype:trojan-activity; sid:2003174; rev:8; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible UTF-16 encoded Shellcode Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/bin/view/Main/2003174

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 8

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 2)"; content:"|82 ed 5f 4c 5d 52 43 78 03 d9 95 8f 84 49 4a 48 71 74 45 d3|"; reference:url,doc.emergingthreats.net/2010385; classtype:shellcode-detect; sid:2010385; rev:4; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010385
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 2)"; content:"|82 ed 5f 4c 5d 52 43 78 03 d9 95 8f 84 49 4a 48 71 74 45 d3|"; reference:url,doc.emergingthreats.net/2010385; classtype:shellcode-detect; sid:2010385; rev:4; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Countdown Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010385

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 4

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 3)"; content:"|9f 90 4b ef a3 76 76 74 97 36 e4 aa bc 46 2f 77 45 6a 69 63|"; reference:url,doc.emergingthreats.net/2010386; classtype:shellcode-detect; sid:2010386; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010386
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 3)"; content:"|9f 90 4b ef a3 76 76 74 97 36 e4 aa bc 46 2f 77 45 6a 69 63|"; reference:url,doc.emergingthreats.net/2010386; classtype:shellcode-detect; sid:2010386; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Countdown Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010386

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 4)"; content:"|64 65 f8 b6 7e 41 cc 6a 53 13 12 4d 57 28 6e 20 2a 2a cc a5|"; reference:url,doc.emergingthreats.net/2010387; classtype:shellcode-detect; sid:2010387; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010387
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 4)"; content:"|64 65 f8 b6 7e 41 cc 6a 53 13 12 4d 57 28 6e 20 2a 2a cc a5|"; reference:url,doc.emergingthreats.net/2010387; classtype:shellcode-detect; sid:2010387; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Countdown Encoded 4)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010387

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 5)"; content:"|17 1c 1a 19 fb 77 80 ce|"; reference:url,doc.emergingthreats.net/2010388; classtype:shellcode-detect; sid:2010388; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010388
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Countdown Encoded 5)"; content:"|17 1c 1a 19 fb 77 80 ce|"; reference:url,doc.emergingthreats.net/2010388; classtype:shellcode-detect; sid:2010388; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Countdown Encoded 5)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010388

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Encoded 1)"; content:"|c9 83 e9 ec e8 ff ff ff ff c0 5e 81 76 0e|"; reference:url,doc.emergingthreats.net/2010389; classtype:shellcode-detect; sid:2010389; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010389
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Encoded 1)"; content:"|c9 83 e9 ec e8 ff ff ff ff c0 5e 81 76 0e|"; reference:url,doc.emergingthreats.net/2010389; classtype:shellcode-detect; sid:2010389; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010389

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Encoded 2)"; content:"|83 ee fc e2 f4|"; reference:url,doc.emergingthreats.net/2010390; classtype:shellcode-detect; sid:2010390; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010390
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Encoded 2)"; content:"|83 ee fc e2 f4|"; reference:url,doc.emergingthreats.net/2010390; classtype:shellcode-detect; sid:2010390; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010390

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 1)"; content:"|6a 61 58 99 52 68 10 02|"; reference:url,doc.emergingthreats.net/2010391; classtype:shellcode-detect; sid:2010391; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010391
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 1)"; content:"|6a 61 58 99 52 68 10 02|"; reference:url,doc.emergingthreats.net/2010391; classtype:shellcode-detect; sid:2010391; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Not Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010391

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 3)"; content:"|80 b0 6a cd 80 52 53 52 b0 1e cd 80 97 6a 02 59 6a 5a 58 51|"; reference:url,doc.emergingthreats.net/2010393; classtype:shellcode-detect; sid:2010393; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010393
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 3)"; content:"|80 b0 6a cd 80 52 53 52 b0 1e cd 80 97 6a 02 59 6a 5a 58 51|"; reference:url,doc.emergingthreats.net/2010393; classtype:shellcode-detect; sid:2010393; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Not Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010393

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 4)"; content:"|57 51 cd 80 49 79 f5 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3|"; reference:url,doc.emergingthreats.net/2010394; classtype:shellcode-detect; sid:2010394; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010394
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 4)"; content:"|57 51 cd 80 49 79 f5 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3|"; reference:url,doc.emergingthreats.net/2010394; classtype:shellcode-detect; sid:2010394; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Not Encoded 4)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010394

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 5)"; content:"|50 54 53 53 b0 3b cd 80|"; reference:url,doc.emergingthreats.net/2010395; classtype:shellcode-detect; sid:2010395; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010395
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Not Encoded 5)"; content:"|50 54 53 53 b0 3b cd 80|"; reference:url,doc.emergingthreats.net/2010395; classtype:shellcode-detect; sid:2010395; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Not Encoded 5)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010395

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 1)"; content:"|eb 03 59 eb 05 e8 f8 ff ff ff 4f 49 49 49 49 49 49 51 5a 56|"; reference:url,doc.emergingthreats.net/2010396; classtype:shellcode-detect; sid:2010396; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010396
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 1)"; content:"|eb 03 59 eb 05 e8 f8 ff ff ff 4f 49 49 49 49 49 49 51 5a 56|"; reference:url,doc.emergingthreats.net/2010396; classtype:shellcode-detect; sid:2010396; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010396

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 2)"; content:"|54 58 36 33 30 56 58 34 41 30 42 36 48 48 30 42 33 30 42 43|"; reference:url,doc.emergingthreats.net/2010397; classtype:shellcode-detect; sid:2010397; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010397
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 2)"; content:"|54 58 36 33 30 56 58 34 41 30 42 36 48 48 30 42 33 30 42 43|"; reference:url,doc.emergingthreats.net/2010397; classtype:shellcode-detect; sid:2010397; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010397

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 3)"; content:"|56 58 32 42 44 42 48 34 41 32 41 44 30 41 44 54 42 44 51 42|"; reference:url,doc.emergingthreats.net/2010398; classtype:shellcode-detect; sid:2010398; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010398
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 3)"; content:"|56 58 32 42 44 42 48 34 41 32 41 44 30 41 44 54 42 44 51 42|"; reference:url,doc.emergingthreats.net/2010398; classtype:shellcode-detect; sid:2010398; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010398

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 4)"; content:"|30 41 44 41 56 58 34 5a 38 42 44 4a 4f 4d 4c 36 41|"; reference:url,doc.emergingthreats.net/2010399; classtype:shellcode-detect; sid:2010399; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010399
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 4)"; content:"|30 41 44 41 56 58 34 5a 38 42 44 4a 4f 4d 4c 36 41|"; reference:url,doc.emergingthreats.net/2010399; classtype:shellcode-detect; sid:2010399; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 4)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010399

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 5)"; content:"|41 4e 44 35 44 34 44|"; reference:url,doc.emergingthreats.net/2010400; classtype:shellcode-detect; sid:2010400; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010400
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 5)"; content:"|41 4e 44 35 44 34 44|"; reference:url,doc.emergingthreats.net/2010400; classtype:shellcode-detect; sid:2010400; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Pex Alphanumeric Encoded 5)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010400

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 1)"; content:"|6a 14 59 d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010401; classtype:shellcode-detect; sid:2010401; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010401
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 1)"; content:"|6a 14 59 d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010401; classtype:shellcode-detect; sid:2010401; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010401

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 2)"; content:"|83 eb fc e2 f4|"; reference:url,doc.emergingthreats.net/2010402; classtype:shellcode-detect; sid:2010402; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010402
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 2)"; content:"|83 eb fc e2 f4|"; reference:url,doc.emergingthreats.net/2010402; classtype:shellcode-detect; sid:2010402; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (PexFstEnvMov Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010402

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (JmpCallAdditive Encoded)"; content:"|eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff|"; reference:url,doc.emergingthreats.net/2010403; classtype:shellcode-detect; sid:2010403; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010403
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (JmpCallAdditive Encoded)"; content:"|eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff|"; reference:url,doc.emergingthreats.net/2010403; classtype:shellcode-detect; sid:2010403; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (JmpCallAdditive Encoded)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010403

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 1)"; content:"|eb 03 59 eb 05 e8 f8 ff ff ff 49 49 49 49 49 49 49 49 49 49|"; reference:url,doc.emergingthreats.net/2010404; classtype:shellcode-detect; sid:2010404; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010404
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 1)"; content:"|eb 03 59 eb 05 e8 f8 ff ff ff 49 49 49 49 49 49 49 49 49 49|"; reference:url,doc.emergingthreats.net/2010404; classtype:shellcode-detect; sid:2010404; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Alpha2 Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010404

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 2)"; content:"|41 42 32 42 41 32 41 41 30 41 41 58|"; reference:url,doc.emergingthreats.net/2010405; classtype:shellcode-detect; sid:2010405; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010405
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 2)"; content:"|41 42 32 42 41 32 41 41 30 41 41 58|"; reference:url,doc.emergingthreats.net/2010405; classtype:shellcode-detect; sid:2010405; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Alpha2 Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010405

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 3)"; content:"|49 72 4e 4e 69 6b 53|"; reference:url,doc.emergingthreats.net/2010406; classtype:shellcode-detect; sid:2010406; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010406
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Bind shell (Alpha2 Encoded 3)"; content:"|49 72 4e 4e 69 6b 53|"; reference:url,doc.emergingthreats.net/2010406; classtype:shellcode-detect; sid:2010406; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Bind shell (Alpha2 Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010406

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (PexFnstenvSub Encoded 1)"; content:"|c9 83 e9 ef d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010407; classtype:shellcode-detect; sid:2010407; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010407
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (PexFnstenvSub Encoded 1)"; content:"|c9 83 e9 ef d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010407; classtype:shellcode-detect; sid:2010407; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (PexFnstenvSub Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010407

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 1)"; content:"|6a 43 59 e8 ff ff ff ff c1 5e 30 4c 0e 07 e2 fa 6b 63 5b 9d|"; reference:url,doc.emergingthreats.net/2010409; classtype:shellcode-detect; sid:2010409; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010409
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 1)"; content:"|6a 43 59 e8 ff ff ff ff c1 5e 30 4c 0e 07 e2 fa 6b 63 5b 9d|"; reference:url,doc.emergingthreats.net/2010409; classtype:shellcode-detect; sid:2010409; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Countdown Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010409

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 2)"; content:"|9f f6 72 09 4b 4b 4d 8a 74 7d 78 ec a2 49 26 7c 96 7d 79 7e|"; reference:url,doc.emergingthreats.net/2010410; classtype:shellcode-detect; sid:2010410; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010410
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 2)"; content:"|9f f6 72 09 4b 4b 4d 8a 74 7d 78 ec a2 49 26 7c 96 7d 79 7e|"; reference:url,doc.emergingthreats.net/2010410; classtype:shellcode-detect; sid:2010410; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Countdown Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010410

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 3)"; content:"|7b e6 ac 64 57 d9 60 59 1d 1c 47 5d 5e 18 5a 50 54 b2 df 6d|"; reference:url,doc.emergingthreats.net/2010411; classtype:shellcode-detect; sid:2010411; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010411
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 3)"; content:"|7b e6 ac 64 57 d9 60 59 1d 1c 47 5d 5e 18 5a 50 54 b2 df 6d|"; reference:url,doc.emergingthreats.net/2010411; classtype:shellcode-detect; sid:2010411; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Countdown Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010411

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 4)"; content:"|57 44 55 4a 5b 62|"; reference:url,doc.emergingthreats.net/2010412; classtype:shellcode-detect; sid:2010412; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010412
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Countdown Encoded 4)"; content:"|57 44 55 4a 5b 62|"; reference:url,doc.emergingthreats.net/2010412; classtype:shellcode-detect; sid:2010412; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Countdown Encoded 4)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010412

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Encoded 1)"; content:"|c9 83 e9 ef e8 ff ff ff ff c0 5e 81 76 0e|"; reference:url,doc.emergingthreats.net/2010413; classtype:shellcode-detect; sid:2010413; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010413
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Encoded 1)"; content:"|c9 83 e9 ef e8 ff ff ff ff c0 5e 81 76 0e|"; reference:url,doc.emergingthreats.net/2010413; classtype:shellcode-detect; sid:2010413; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Pex Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010413

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Encoded 2)"; content:"|83 ee fc e2 f4|"; reference:url,doc.emergingthreats.net/2010414; classtype:shellcode-detect; sid:2010414; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010414
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Encoded 2)"; content:"|83 ee fc e2 f4|"; reference:url,doc.emergingthreats.net/2010414; classtype:shellcode-detect; sid:2010414; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Pex Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010414

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 1)"; content:"|51 cd 80 49 79 f6 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50|"; reference:url,doc.emergingthreats.net/2010415; classtype:shellcode-detect; sid:2010415; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010415
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 1)"; content:"|51 cd 80 49 79 f6 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50|"; reference:url,doc.emergingthreats.net/2010415; classtype:shellcode-detect; sid:2010415; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Not Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010415

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 2)"; content:"|6a 61 58 99 52 42 52 42 52 68|"; reference:url,doc.emergingthreats.net/2010416; classtype:shellcode-detect; sid:2010416; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010416
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 2)"; content:"|6a 61 58 99 52 42 52 42 52 68|"; reference:url,doc.emergingthreats.net/2010416; classtype:shellcode-detect; sid:2010416; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Not Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010416

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 3)"; content:"|89 e1 6a 10 51 50 51 97 6a 62 58 cd 80 6a 02 59 b0 5a 51 57|"; reference:url,doc.emergingthreats.net/2010417; classtype:shellcode-detect; sid:2010417; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010417
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Not Encoded 3)"; content:"|89 e1 6a 10 51 50 51 97 6a 62 58 cd 80 6a 02 59 b0 5a 51 57|"; reference:url,doc.emergingthreats.net/2010417; classtype:shellcode-detect; sid:2010417; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Not Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010417

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 1)"; content:"|44 32 4d 4c 42 48 4a 46 42 31 44 50 50 41 4e 4f 49 38 41 4e|"; reference:url,doc.emergingthreats.net/2010418; classtype:shellcode-detect; sid:2010418; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010418
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 1)"; content:"|44 32 4d 4c 42 48 4a 46 42 31 44 50 50 41 4e 4f 49 38 41 4e|"; reference:url,doc.emergingthreats.net/2010418; classtype:shellcode-detect; sid:2010418; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010418

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 2)"; content:"|4c 36 42 41 41 35 42 45 41 35 47 59 4c 36 44 56 4a 35 4d 4c|"; reference:url,doc.emergingthreats.net/2010419; classtype:shellcode-detect; sid:2010419; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010419
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 2)"; content:"|4c 36 42 41 41 35 42 45 41 35 47 59 4c 36 44 56 4a 35 4d 4c|"; reference:url,doc.emergingthreats.net/2010419; classtype:shellcode-detect; sid:2010419; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 2)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010419

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 3)"; content:"|56 58 32 42 44 42 48 34 41 32 41 44 30 41 44 54 42 44 51 42|"; reference:url,doc.emergingthreats.net/2010420; classtype:shellcode-detect; sid:2010420; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010420
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 3)"; content:"|56 58 32 42 44 42 48 34 41 32 41 44 30 41 44 54 42 44 51 42|"; reference:url,doc.emergingthreats.net/2010420; classtype:shellcode-detect; sid:2010420; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (Pex Alphanumeric Encoded 3)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010420

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (PexFnstenvMov Encoded 1)"; content:"|6a 11 59 d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010421; classtype:shellcode-detect; sid:2010421; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)

# 2010421
`#alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE METASPLOIT BSD Reverse shell (PexFnstenvMov Encoded 1)"; content:"|6a 11 59 d9 ee d9 74 24 f4 5b 81 73 13|"; reference:url,doc.emergingthreats.net/2010421; classtype:shellcode-detect; sid:2010421; rev:3; metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **METASPLOIT BSD Reverse shell (PexFnstenvMov Encoded 1)** 

Attack target : Client_and_Server

Description : The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
Its best-known project is the open source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
The Metasploit Project is well known for its anti-forensic and evasion tools, some of which are built into the Metasploit Framework (MSF).
Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. Shellcode is commonly written in machine code.

These alerts will fire when shellcode known to be part of Metasploit Project is detected traversing the network. This indicates active use of Metasploit Framework, and it will fire very frequently during a penetration test. If you see only one or two alerts, it may indicate the attacker has copied the shellcode from Metasploit. There have been a few examples of its use in APT campaigns for persistence and lateral movement. 1,2

Tags : Metasploit

Affected products : Any

Alert Classtype : shellcode-detect

URL reference : url,doc.emergingthreats.net/2010421

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible TCP x86 JMP to CALL Shellcode Detected"; flow:established; content:"|EB|"; byte_jump:1,0,relative; content:"|E8|"; within:1; content:"|FF FF FF|"; distance:1; within:3; content:!"MZ"; content:!"This program cannot be run in DOS mode"; content:!"Windows Program"; reference:url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/; classtype:shellcode-detect; sid:2011803; rev:5; metadata:created_at 2010_10_12, updated_at 2010_10_12;)

# 2011803
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible TCP x86 JMP to CALL Shellcode Detected"; flow:established; content:"|EB|"; byte_jump:1,0,relative; content:"|E8|"; within:1; content:"|FF FF FF|"; distance:1; within:3; content:!"MZ"; content:!"This program cannot be run in DOS mode"; content:!"Windows Program"; reference:url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/; classtype:shellcode-detect; sid:2011803; rev:5; metadata:created_at 2010_10_12, updated_at 2010_10_12;)
` 

Name : **Possible TCP x86 JMP to CALL Shellcode Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2010-10-12

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UDP x86 JMP to CALL Shellcode Detected"; content:"|EB|"; byte_jump:1,0,relative; content:"|E8|"; within:1; content:"|FF FF FF|"; distance:1; within:3; reference:url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/; classtype:shellcode-detect; sid:2011804; rev:2; metadata:created_at 2010_10_12, updated_at 2010_10_12;)

# 2011804
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UDP x86 JMP to CALL Shellcode Detected"; content:"|EB|"; byte_jump:1,0,relative; content:"|E8|"; within:1; content:"|FF FF FF|"; distance:1; within:3; reference:url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/; classtype:shellcode-detect; sid:2011804; rev:2; metadata:created_at 2010_10_12, updated_at 2010_10_12;)
` 

Name : **Possible UDP x86 JMP to CALL Shellcode Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.networkforensics.com/2010/05/16/network-detection-of-x86-buffer-overflow-shellcode/

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2010-10-12

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible Usage of Actionscript ByteArray writeByte Function to Build Shellcode"; flow:established,to_client; content:"writeByte(0x"; nocase; pcre:"/writeByte\x280x[a-z,0-9]{2}.+writeByte\x280x[a-z,0-9]{2}.+writeByte\x280x[a-z,0-9]{2}/smi"; reference:url,blog.fireeye.com/research/2009/07/actionscript_heap_spray.html; classtype:shellcode-detect; sid:2012120; rev:2; metadata:created_at 2010_12_30, updated_at 2010_12_30;)

# 2012120
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible Usage of Actionscript ByteArray writeByte Function to Build Shellcode"; flow:established,to_client; content:"writeByte(0x"; nocase; pcre:"/writeByte\x280x[a-z,0-9]{2}.+writeByte\x280x[a-z,0-9]{2}.+writeByte\x280x[a-z,0-9]{2}/smi"; reference:url,blog.fireeye.com/research/2009/07/actionscript_heap_spray.html; classtype:shellcode-detect; sid:2012120; rev:2; metadata:created_at 2010_12_30, updated_at 2010_12_30;)
` 

Name : **Possible Usage of Actionscript ByteArray writeByte Function to Build Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,blog.fireeye.com/research/2009/07/actionscript_heap_spray.html

CVE reference : Not defined

Creation date : 2010-12-30

Last modified date : 2010-12-30

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Common %0a%0a%0a%0a Heap Spray String"; flow:established,to_client; content:"%0a%0a%0a%0a"; nocase; fast_pattern:only; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012253; rev:2; metadata:created_at 2011_02_02, updated_at 2011_02_02;)

# 2012253
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Common %0a%0a%0a%0a Heap Spray String"; flow:established,to_client; content:"%0a%0a%0a%0a"; nocase; fast_pattern:only; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012253; rev:2; metadata:created_at 2011_02_02, updated_at 2011_02_02;)
` 

Name : **Common %0a%0a%0a%0a Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2011-02-02

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Common 0c0c0c0c Heap Spray String"; flow:established,to_client; content:"0c0c0c0c"; nocase; fast_pattern:only; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012256; rev:2; metadata:created_at 2011_02_02, updated_at 2011_02_02;)

# 2012256
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Common 0c0c0c0c Heap Spray String"; flow:established,to_client; content:"0c0c0c0c"; nocase; fast_pattern:only; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012256; rev:2; metadata:created_at 2011_02_02, updated_at 2011_02_02;)
` 

Name : **Common 0c0c0c0c Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2011-02-02

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE UTF-8/16 Encoded Shellcode"; flow:established,to_client; content:"|5C|u"; nocase; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; pcre:"/\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}/i"; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:bad-unknown; sid:2012510; rev:2; metadata:created_at 2011_03_16, updated_at 2011_03_16;)

# 2012510
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE UTF-8/16 Encoded Shellcode"; flow:established,to_client; content:"|5C|u"; nocase; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; content:"|5C|u"; nocase; within:6; pcre:"/\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}/i"; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:bad-unknown; sid:2012510; rev:2; metadata:created_at 2011_03_16, updated_at 2011_03_16;)
` 

Name : **UTF-8/16 Encoded Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html

CVE reference : Not defined

Creation date : 2011-03-16

Last modified date : 2011-03-16

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Variable %u Shellcode"; flow:established,to_client; content:"= unescape|28|"; nocase; content:"%u"; nocase; within:3; content:"%u"; nocase; within:6; pcre:"/var\x20[a-z,0-9]{1,30}\x20\x3D\x20unescape\x28.\x25u[a-f,0-9]{2,4}\x25u[a-f,0-9]{2,4}/i"; reference:url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf; classtype:shellcode-detect; sid:2012534; rev:2; metadata:created_at 2011_03_22, updated_at 2011_03_22;)

# 2012534
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Variable %u Shellcode"; flow:established,to_client; content:"= unescape|28|"; nocase; content:"%u"; nocase; within:3; content:"%u"; nocase; within:6; pcre:"/var\x20[a-z,0-9]{1,30}\x20\x3D\x20unescape\x28.\x25u[a-f,0-9]{2,4}\x25u[a-f,0-9]{2,4}/i"; reference:url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf; classtype:shellcode-detect; sid:2012534; rev:2; metadata:created_at 2011_03_22, updated_at 2011_03_22;)
` 

Name : **Unescape Variable %u Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf

CVE reference : Not defined

Creation date : 2011-03-22

Last modified date : 2011-03-22

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Variable Unicode Shellcode"; flow:established,to_client; content:"= unescape|28|"; nocase; content:"|5C|u"; nocase; within:3; content:"|5C|u"; nocase; within:6; pcre:"/var\x20[a-z,0-9]{1,30}\x20\x3D\x20unescape\x28.\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}/i"; reference:url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf; classtype:shellcode-detect; sid:2012535; rev:2; metadata:created_at 2011_03_22, updated_at 2011_03_22;)

# 2012535
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Variable Unicode Shellcode"; flow:established,to_client; content:"= unescape|28|"; nocase; content:"|5C|u"; nocase; within:3; content:"|5C|u"; nocase; within:6; pcre:"/var\x20[a-z,0-9]{1,30}\x20\x3D\x20unescape\x28.\x5Cu[a-f,0-9]{2,4}\x5Cu[a-f,0-9]{2,4}/i"; reference:url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf; classtype:shellcode-detect; sid:2012535; rev:2; metadata:created_at 2011_03_22, updated_at 2011_03_22;)
` 

Name : **Unescape Variable Unicode Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.symantec.com/avcenter/reference/evolving.shell.code.pdf

CVE reference : Not defined

Creation date : 2011-03-22

Last modified date : 2011-03-22

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE AIX NOOP"; content:"O|FF FB 82|O|FF FB 82|O|FF FB 82|O|FF FB 82|"; classtype:shellcode-detect; sid:2100640; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100640
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE AIX NOOP"; content:"O|FF FB 82|O|FF FB 82|O|FF FB 82|O|FF FB 82|"; classtype:shellcode-detect; sid:2100640; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AIX NOOP** 

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

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Javascript Split String Unicode Heap Spray Attempt"; flow:established,to_client; content:"|22|u|22 20|+|20 22|0|22 20|+|20 22|"; content:"|22 20|+|20 22|"; distance:1; within:5; pcre:"/\x220\x22\x20\x2B\x20\x22[a-d]\x22\x20\x2B\x20\x22/smi"; classtype:shellcode-detect; sid:2012925; rev:2; metadata:created_at 2011_06_02, updated_at 2011_06_02;)

# 2012925
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Javascript Split String Unicode Heap Spray Attempt"; flow:established,to_client; content:"|22|u|22 20|+|20 22|0|22 20|+|20 22|"; content:"|22 20|+|20 22|"; distance:1; within:5; pcre:"/\x220\x22\x20\x2B\x20\x22[a-d]\x22\x20\x2B\x20\x22/smi"; classtype:shellcode-detect; sid:2012925; rev:2; metadata:created_at 2011_06_02, updated_at 2011_06_02;)
` 

Name : **Javascript Split String Unicode Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-02

Last modified date : 2011-06-02

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0b0b0b0b Heap Spray Attempt"; flow:established,to_client; content:"0x0b0b0b0b"; nocase; classtype:shellcode-detect; sid:2012963; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012963
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0b0b0b0b Heap Spray Attempt"; flow:established,to_client; content:"0x0b0b0b0b"; nocase; classtype:shellcode-detect; sid:2012963; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible 0x0b0b0b0b Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Vertical Slash Unicode Heap Spray Attempt"; flow:established,to_client; content:"|7C|u0"; nocase; content:"|7C|u0"; distance:1; within:4; pcre:"/\x7Cu0[a-d](\x7Cu0|0)[a-d]/\x7Cu0[a-d](\x7Cu0|0)[a-d]/i"; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012969; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012969
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Vertical Slash Unicode Heap Spray Attempt"; flow:established,to_client; content:"|7C|u0"; nocase; content:"|7C|u0"; distance:1; within:4; pcre:"/\x7Cu0[a-d](\x7Cu0|0)[a-d]/\x7Cu0[a-d](\x7Cu0|0)[a-d]/i"; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012969; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible Vertical Slash Unicode Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Unicode Heap Spray Attempt"; flow:established,to_client; content:"|5C|u0"; nocase; content:"|5C|u0"; distance:1; within:4; pcre:"/\x5Cu0[a-d](\x5Cu0|0)[a-d]/\x5Cu0[a-d](\x5Cu0|0)[a-d]/i"; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012970; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012970
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Unicode Heap Spray Attempt"; flow:established,to_client; content:"|5C|u0"; nocase; content:"|5C|u0"; distance:1; within:4; pcre:"/\x5Cu0[a-d](\x5Cu0|0)[a-d]/\x5Cu0[a-d](\x5Cu0|0)[a-d]/i"; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012970; rev:2; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible Backslash Unicode Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE JavaScript Redefinition of a HeapLib Object - Likely Malicious Heap Spray Attempt"; flow:established,to_client; content:"heap|2E|"; nocase; fast_pattern:only; pcre:"/var\x20[^\n\r]*\x3D[^\n\r]*heap\x2E/smi"; classtype:shellcode-detect; sid:2013148; rev:3; metadata:created_at 2011_06_30, updated_at 2011_06_30;)

# 2013148
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE JavaScript Redefinition of a HeapLib Object - Likely Malicious Heap Spray Attempt"; flow:established,to_client; content:"heap|2E|"; nocase; fast_pattern:only; pcre:"/var\x20[^\n\r]*\x3D[^\n\r]*heap\x2E/smi"; classtype:shellcode-detect; sid:2013148; rev:3; metadata:created_at 2011_06_30, updated_at 2011_06_30;)
` 

Name : **JavaScript Redefinition of a HeapLib Object - Likely Malicious Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-30

Last modified date : 2011-06-30

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 41414141"; flow:established,to_client; content:"|5C|x41|5C|x41|5C|x41|5C|x41"; nocase; fast_pattern:only; metadata: former_category SHELLCODE; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013273; rev:2; metadata:created_at 2011_07_14, updated_at 2017_09_08;)

# 2013273
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 41414141"; flow:established,to_client; content:"|5C|x41|5C|x41|5C|x41|5C|x41"; nocase; fast_pattern:only; metadata: former_category SHELLCODE; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013273; rev:2; metadata:created_at 2011_07_14, updated_at 2017_09_08;)
` 

Name : **Hex Obfuscated JavaScript Heap Spray 41414141** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2017-09-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unicode UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"u0"; nocase; content:"u0"; nocase; distance:1; within:2; content:"u0"; nocase; distance:1; within:2; content:"u0"; nocase; distance:1; within:2; pcre:"/u0[a-d]u0[a-d]u0[a-d]u0[a-d]/smi"; classtype:shellcode-detect; sid:2013319; rev:2; metadata:created_at 2011_07_27, updated_at 2011_07_27;)

# 2013319
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unicode UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"u0"; nocase; content:"u0"; nocase; distance:1; within:2; content:"u0"; nocase; distance:1; within:2; content:"u0"; nocase; distance:1; within:2; pcre:"/u0[a-d]u0[a-d]u0[a-d]u0[a-d]/smi"; classtype:shellcode-detect; sid:2013319; rev:2; metadata:created_at 2011_07_27, updated_at 2011_07_27;)
` 

Name : **Unicode UTF-8 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-27

Last modified date : 2011-07-27

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unicode UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"u0"; nocase; content:"u0"; nocase; distance:3; within:2; pcre:"/u0[a-d]0[a-d]u0[a-d]0[a-d]/smi"; classtype:shellcode-detect; sid:2013320; rev:2; metadata:created_at 2011_07_27, updated_at 2011_07_27;)

# 2013320
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unicode UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"u0"; nocase; content:"u0"; nocase; distance:3; within:2; pcre:"/u0[a-d]0[a-d]u0[a-d]0[a-d]/smi"; classtype:shellcode-detect; sid:2013320; rev:2; metadata:created_at 2011_07_27, updated_at 2011_07_27;)
` 

Name : **Unicode UTF-16 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-27

Last modified date : 2011-07-27

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0a0a0a0a Heap Spray Attempt"; flow:established,to_client; content:"0x0a0a0a0a"; nocase; classtype:shellcode-detect; sid:2012962; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012962
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0a0a0a0a Heap Spray Attempt"; flow:established,to_client; content:"0x0a0a0a0a"; nocase; classtype:shellcode-detect; sid:2012962; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible 0x0a0a0a0a Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0c0c0c0c Heap Spray Attempt"; flow:established,to_client; content:"0x0c0c0c0c"; nocase; classtype:shellcode-detect; sid:2012964; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012964
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0c0c0c0c Heap Spray Attempt"; flow:established,to_client; content:"0x0c0c0c0c"; nocase; classtype:shellcode-detect; sid:2012964; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible 0x0c0c0c0c Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0d0d0d0d Heap Spray Attempt"; flow:established,to_client; content:"0x0d0d0d0d"; nocase; classtype:shellcode-detect; sid:2012965; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012965
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible 0x0d0d0d0d Heap Spray Attempt"; flow:established,to_client; content:"0x0d0d0d0d"; nocase; classtype:shellcode-detect; sid:2012965; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible 0x0d0d0d0d Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %0d%0d%0d%0d Heap Spray Attempt"; flow:established,to_client; content:"%0d%0d%0d%0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012966; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012966
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %0d%0d%0d%0d Heap Spray Attempt"; flow:established,to_client; content:"%0d%0d%0d%0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012966; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible %0d%0d%0d%0d Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u0d%u0d%u0d%u0d UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"%u0d%u0d%u0d%u0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012967; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012967
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u0d%u0d%u0d%u0d UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"%u0d%u0d%u0d%u0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012967; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible %u0d%u0d%u0d%u0d UTF-8 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u0d0d%u0d0d UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"%u0d0d%u0d0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012968; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)

# 2012968
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u0d0d%u0d0d UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"%u0d0d%u0d0d"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012968; rev:3; metadata:created_at 2011_06_08, updated_at 2011_06_08;)
` 

Name : **Possible %u0d0d%u0d0d UTF-16 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-06-08

Last modified date : 2011-06-08

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape %u Shellcode/Heap Spray"; flow:established,to_client; content:"unescape"; nocase; content:"%u"; nocase; distance:0; content:"%u"; nocase; within:6; pcre:"/unescape.+\x25u[0-9,a-f]{2,4}\x25u[0-9,a-f]{2,4}/smi"; reference:url,www.w3schools.com/jsref/jsref_unescape.asp; reference:url,isc.sans.org/diary.html?storyid=7906; reference:url,isc.sans.org/diary.html?storyid=7903; reference:url,malzilla.sourceforge.net/tutorial01/index.html; reference:url,doc.emergingthreats.net/2011346; classtype:shellcode-detect; sid:2011346; rev:7; metadata:created_at 2010_09_28, updated_at 2010_09_28;)

# 2011346
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape %u Shellcode/Heap Spray"; flow:established,to_client; content:"unescape"; nocase; content:"%u"; nocase; distance:0; content:"%u"; nocase; within:6; pcre:"/unescape.+\x25u[0-9,a-f]{2,4}\x25u[0-9,a-f]{2,4}/smi"; reference:url,www.w3schools.com/jsref/jsref_unescape.asp; reference:url,isc.sans.org/diary.html?storyid=7906; reference:url,isc.sans.org/diary.html?storyid=7903; reference:url,malzilla.sourceforge.net/tutorial01/index.html; reference:url,doc.emergingthreats.net/2011346; classtype:shellcode-detect; sid:2011346; rev:7; metadata:created_at 2010_09_28, updated_at 2010_09_28;)
` 

Name : **Possible Unescape %u Shellcode/Heap Spray** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.w3schools.com/jsref/jsref_unescape.asp|url,isc.sans.org/diary.html?storyid=7906|url,isc.sans.org/diary.html?storyid=7903|url,malzilla.sourceforge.net/tutorial01/index.html|url,doc.emergingthreats.net/2011346

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2010-09-28

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Hex Obfuscated Content"; flow:established,to_client; content:"unescape|28|"; fast_pattern; content:"|5C|x"; distance:1; within:2; content:"|5C|x"; distance:2; within:2; content:"|5C|x"; distance:2; within:2; content:"|5C|x"; distance:2; within:2; pcre:"/unescape\x28(\x22|\x27)\x5Cx[a-f,0-9]{2}\x5Cx[a-f,0-9]{2}\x5Cx[a-f,0-9]{2}/smi"; classtype:shellcode-detect; sid:2013272; rev:3; metadata:created_at 2011_07_14, updated_at 2011_07_14;)

# 2013272
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Unescape Hex Obfuscated Content"; flow:established,to_client; content:"unescape|28|"; fast_pattern; content:"|5C|x"; distance:1; within:2; content:"|5C|x"; distance:2; within:2; content:"|5C|x"; distance:2; within:2; content:"|5C|x"; distance:2; within:2; pcre:"/unescape\x28(\x22|\x27)\x5Cx[a-f,0-9]{2}\x5Cx[a-f,0-9]{2}\x5Cx[a-f,0-9]{2}/smi"; classtype:shellcode-detect; sid:2013272; rev:3; metadata:created_at 2011_07_14, updated_at 2011_07_14;)
` 

Name : **Unescape Hex Obfuscated Content** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2011-07-14

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x71FB7BAB NOOP unicode"; content:"q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|"; classtype:shellcode-detect; sid:2102313; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102313
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x71FB7BAB NOOP unicode"; content:"q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|q|00 FB 00|{|00 AB 00|"; classtype:shellcode-detect; sid:2102313; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 0x71FB7BAB NOOP unicode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x71FB7BAB NOOP"; content:"q|FB|{|AB|q|FB|{|AB|q|FB|{|AB|q|FB|{|AB|"; classtype:shellcode-detect; sid:2102312; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102312
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x71FB7BAB NOOP"; content:"q|FB|{|AB|q|FB|{|AB|q|FB|{|AB|q|FB|{|AB|"; classtype:shellcode-detect; sid:2102312; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 0x71FB7BAB NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE SGI NOOP"; content:"|03 E0 F8|%|03 E0 F8|%|03 E0 F8|%|03 E0 F8|%"; reference:arachnids,356; classtype:shellcode-detect; sid:2100638; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100638
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE SGI NOOP"; content:"|03 E0 F8|%|03 E0 F8|%|03 E0 F8|%|03 E0 F8|%"; reference:arachnids,356; classtype:shellcode-detect; sid:2100638; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SGI NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,356

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE SGI NOOP"; content:"|24 0F 12|4|24 0F 12|4|24 0F 12|4|24 0F 12|4"; reference:arachnids,357; classtype:shellcode-detect; sid:2100639; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100639
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE SGI NOOP"; content:"|24 0F 12|4|24 0F 12|4|24 0F 12|4|24 0F 12|4"; reference:arachnids,357; classtype:shellcode-detect; sid:2100639; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SGI NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,357

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE Digital UNIX NOOP"; content:"G|FF 04 1F|G|FF 04 1F|G|FF 04 1F|G|FF 04 1F|"; reference:arachnids,352; classtype:shellcode-detect; sid:2100641; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100641
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE Digital UNIX NOOP"; content:"G|FF 04 1F|G|FF 04 1F|G|FF 04 1F|G|FF 04 1F|"; reference:arachnids,352; classtype:shellcode-detect; sid:2100641; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Digital UNIX NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,352

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE HP-UX NOOP"; content:"|08|!|02 80 08|!|02 80 08|!|02 80 08|!|02 80|"; reference:arachnids,358; classtype:shellcode-detect; sid:2100642; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100642
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE HP-UX NOOP"; content:"|08|!|02 80 08|!|02 80 08|!|02 80 08|!|02 80|"; reference:arachnids,358; classtype:shellcode-detect; sid:2100642; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **HP-UX NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,358

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE HP-UX NOOP"; content:"|0B|9|02 80 0B|9|02 80 0B|9|02 80 0B|9|02 80|"; reference:arachnids,359; classtype:shellcode-detect; sid:2100643; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100643
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE HP-UX NOOP"; content:"|0B|9|02 80 0B|9|02 80 0B|9|02 80 0B|9|02 80|"; reference:arachnids,359; classtype:shellcode-detect; sid:2100643; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **HP-UX NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,359

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|13 C0 1C A6 13 C0 1C A6 13 C0 1C A6 13 C0 1C A6|"; reference:arachnids,345; classtype:shellcode-detect; sid:2100644; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100644
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|13 C0 1C A6 13 C0 1C A6 13 C0 1C A6 13 C0 1C A6|"; reference:arachnids,345; classtype:shellcode-detect; sid:2100644; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sparc NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,345

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|80 1C|@|11 80 1C|@|11 80 1C|@|11 80 1C|@|11|"; reference:arachnids,353; classtype:shellcode-detect; sid:2100645; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100645
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|80 1C|@|11 80 1C|@|11 80 1C|@|11 80 1C|@|11|"; reference:arachnids,353; classtype:shellcode-detect; sid:2100645; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sparc NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,353

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|A6 1C C0 13 A6 1C C0 13 A6 1C C0 13 A6 1C C0 13|"; reference:arachnids,355; classtype:shellcode-detect; sid:2100646; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100646
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc NOOP"; content:"|A6 1C C0 13 A6 1C C0 13 A6 1C C0 13 A6 1C C0 13|"; reference:arachnids,355; classtype:shellcode-detect; sid:2100646; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sparc NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,355

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc setuid 0"; content:"|82 10| |17 91 D0| |08|"; reference:arachnids,282; classtype:system-call-detect; sid:2100647; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100647
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE sparc setuid 0"; content:"|82 10| |17 91 D0| |08|"; reference:arachnids,282; classtype:system-call-detect; sid:2100647; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **sparc setuid 0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : system-call-detect

URL reference : arachnids,282

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:2100649; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100649
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:2100649; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 setgid 0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : system-call-detect

URL reference : arachnids,284

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 setuid 0"; content:"|B0 17 CD 80|"; reference:arachnids,436; classtype:system-call-detect; sid:2100650; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100650
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 setuid 0"; content:"|B0 17 CD 80|"; reference:arachnids,436; classtype:system-call-detect; sid:2100650; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 setuid 0** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : system-call-detect

URL reference : arachnids,436

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 9

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 stealth NOOP"; content:"|EB 02 EB 02 EB 02|"; metadata: former_category SHELLCODE; reference:arachnids,291; classtype:shellcode-detect; sid:2100651; rev:9; metadata:created_at 2010_09_23, updated_at 2017_09_08;)

# 2100651
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 stealth NOOP"; content:"|EB 02 EB 02 EB 02|"; metadata: former_category SHELLCODE; reference:arachnids,291; classtype:shellcode-detect; sid:2100651; rev:9; metadata:created_at 2010_09_23, updated_at 2017_09_08;)
` 

Name : **x86 stealth NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,291

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2017-09-08

Rev version : 9

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE Linux shellcode"; content:"|90 90 90 E8 C0 FF FF FF|/bin/sh"; reference:arachnids,343; classtype:shellcode-detect; sid:2100652; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100652
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE Linux shellcode"; content:"|90 90 90 E8 C0 FF FF FF|/bin/sh"; reference:arachnids,343; classtype:shellcode-detect; sid:2100652; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Linux shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,343

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 inc ebx NOOP"; content:"CCCCCCCCCCCCCCCCCCCCCCCC"; metadata: former_category SHELLCODE; classtype:shellcode-detect; sid:2101390; rev:6; metadata:created_at 2010_09_23, updated_at 2017_09_08;)

# 2101390
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 inc ebx NOOP"; content:"CCCCCCCCCCCCCCCCCCCCCCCC"; metadata: former_category SHELLCODE; classtype:shellcode-detect; sid:2101390; rev:6; metadata:created_at 2010_09_23, updated_at 2017_09_08;)
` 

Name : **x86 inc ebx NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2017-09-08

Rev version : 6

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SHELLCODE ssh CRC32 overflow /bin/sh"; flow:to_server,established; content:"/bin/sh"; reference:bugtraq,2347; reference:cve,2001-0144; reference:cve,2001-0572; classtype:shellcode-detect; sid:2101324; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101324
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SHELLCODE ssh CRC32 overflow /bin/sh"; flow:to_server,established; content:"/bin/sh"; reference:bugtraq,2347; reference:cve,2001-0144; reference:cve,2001-0572; classtype:shellcode-detect; sid:2101324; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ssh CRC32 overflow /bin/sh** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : bugtraq,2347|cve,2001-0144|cve,2001-0572

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SHELLCODE ssh CRC32 overflow NOOP"; flow:to_server,established; content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|"; reference:bugtraq,2347; reference:cve,2001-0144; reference:cve,2001-0572; classtype:shellcode-detect; sid:2101326; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101326
`#alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"GPL SHELLCODE ssh CRC32 overflow NOOP"; flow:to_server,established; content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|"; reference:bugtraq,2347; reference:cve,2001-0144; reference:cve,2001-0572; classtype:shellcode-detect; sid:2101326; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **ssh CRC32 overflow NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : bugtraq,2347|cve,2001-0144|cve,2001-0572

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0b0b0b0b"; flow:established,to_client; file_data; content:"|5C|x0b|5C|x0b|5C|x0b|5C|x0b"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013268; rev:4; metadata:created_at 2011_07_14, updated_at 2011_07_14;)

# 2013268
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0b0b0b0b"; flow:established,to_client; file_data; content:"|5C|x0b|5C|x0b|5C|x0b|5C|x0b"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013268; rev:4; metadata:created_at 2011_07_14, updated_at 2011_07_14;)
` 

Name : **Hex Obfuscated JavaScript Heap Spray 0b0b0b0b** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2011-07-14

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Escaped UTF-8 0c0c Heap Spray"; flow:established,to_client; file_data; content:"|5C|0c|5C|0c"; nocase; distance:0; classtype:bad-unknown; sid:2016714; rev:2; metadata:created_at 2013_04_03, updated_at 2013_04_03;)

# 2016714
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Escaped UTF-8 0c0c Heap Spray"; flow:established,to_client; file_data; content:"|5C|0c|5C|0c"; nocase; distance:0; classtype:bad-unknown; sid:2016714; rev:2; metadata:created_at 2013_04_03, updated_at 2013_04_03;)
` 

Name : **Possible Backslash Escaped UTF-8 0c0c Heap Spray** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-03

Last modified date : 2013-04-03

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Escaped UTF-16 0c0c Heap Spray"; flow:established,to_client; file_data; content:"|5C|0c0c"; nocase; distance:0; metadata: former_category SHELLCODE; classtype:bad-unknown; sid:2016715; rev:2; metadata:created_at 2013_04_03, updated_at 2017_09_08;)

# 2016715
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Backslash Escaped UTF-16 0c0c Heap Spray"; flow:established,to_client; file_data; content:"|5C|0c0c"; nocase; distance:0; metadata: former_category SHELLCODE; classtype:bad-unknown; sid:2016715; rev:2; metadata:created_at 2013_04_03, updated_at 2017_09_08;)
` 

Name : **Possible Backslash Escaped UTF-16 0c0c Heap Spray** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-04-03

Last modified date : 2017-09-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 u9090 NOP SLED"; file_data; flow:established,to_client; content:"|5c|u9090|5c|"; nocase; pcre:"/^[a-f0-9]{4}/Ri"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2017345; rev:4; metadata:created_at 2013_08_19, updated_at 2013_08_19;)

# 2017345
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 u9090 NOP SLED"; file_data; flow:established,to_client; content:"|5c|u9090|5c|"; nocase; pcre:"/^[a-f0-9]{4}/Ri"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2017345; rev:4; metadata:created_at 2013_08_19, updated_at 2013_08_19;)
` 

Name : **Possible UTF-16 u9090 NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html|url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html

CVE reference : Not defined

Creation date : 2013-08-19

Last modified date : 2013-08-19

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 NOOP"; content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90|"; depth:128; reference:arachnids,181; classtype:shellcode-detect; sid:2100648; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100648
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 NOOP"; content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90|"; depth:128; reference:arachnids,181; classtype:shellcode-detect; sid:2100648; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : arachnids,181

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x90 unicode NOOP"; content:"|90 00 90 00 90 00 90 00 90 00|"; classtype:shellcode-detect; sid:2100653; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100653
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x90 unicode NOOP"; content:"|90 00 90 00 90 00 90 00 90 00|"; classtype:shellcode-detect; sid:2100653; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **x86 0x90 unicode NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 8F|"; fast_pattern:only; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012089; rev:2; metadata:created_at 2010_12_23, updated_at 2017_09_08;)

# 2012089
`#alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 8F|"; fast_pattern:only; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012089; rev:2; metadata:created_at 2010_12_23, updated_at 2017_09_08;)
` 

Name : **Possible Call with No Offset UDP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2017-09-08

Rev version : 2

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x90 NOOP unicode"; content:"|90 00 90 00 90 00 90 00 90 00 90 00 90 00 90 00|"; classtype:shellcode-detect; sid:2102314; rev:4; metadata:created_at 2010_09_23, updated_at 2016_09_09;)

# 2102314
`#alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0x90 NOOP unicode"; content:"|90 00 90 00 90 00 90 00 90 00 90 00 90 00 90 00|"; classtype:shellcode-detect; sid:2102314; rev:4; metadata:created_at 2010_09_23, updated_at 2016_09_09;)
` 

Name : **x86 0x90 NOOP unicode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2016-09-09

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 8F|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012088; rev:3; metadata:created_at 2010_12_23, updated_at 2016_09_16;)

# 2012088
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 8F|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012088; rev:3; metadata:created_at 2010_12_23, updated_at 2016_09_16;)
` 

Name : **Possible Call with No Offset TCP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2016-09-16

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Execve(/bin/sh) Shellcode"; content:"|31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80|"; metadata: former_category SHELLCODE; classtype:shellcode-detect; sid:2025695; rev:1; metadata:affected_product Linux, attack_target Server, deployment Perimeter, created_at 2018_07_13, performance_impact Low, updated_at 2018_07_13;)

# 2025695
`alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Execve(/bin/sh) Shellcode"; content:"|31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80|"; metadata: former_category SHELLCODE; classtype:shellcode-detect; sid:2025695; rev:1; metadata:affected_product Linux, attack_target Server, deployment Perimeter, created_at 2018_07_13, performance_impact Low, updated_at 2018_07_13;)
` 

Name : **Execve(/bin/sh) Shellcode** 

Attack target : Server

Description : This signature will detect the Execve /bin/sh shellcode

Tags : Not defined

Affected products : Linux

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2018-07-13

Last modified date : 2018-07-13

Rev version : 1

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 58|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012087; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012087
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 58|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012087; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **Possible Call with No Offset UDP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 0F 1A|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012091; rev:4; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012091
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 0F 1A|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012091; rev:4; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **Possible Call with No Offset UDP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 0F A9|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012093; rev:4; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012093
`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset UDP Shellcode"; content:"|E8 00 00 00 00 0F A9|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012093; rev:4; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **Possible Call with No Offset UDP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 0F A9|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012092; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012092
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 0F A9|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012092; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **Possible Call with No Offset TCP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 0F 1A|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012090; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012090
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Call with No Offset TCP Shellcode"; flow:established; content:"|E8 00 00 00 00 0F 1A|"; metadata: former_category SHELLCODE; reference:url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode; classtype:shellcode-detect; sid:2012090; rev:3; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **Possible Call with No Offset TCP Shellcode** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,community.rsa.com/community/products/netwitness/blog/2012/08/22/network-detection-of-x86-buffer-overflow-shellcode

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape Encoded Content With Split String Obfuscation"; flow:established,to_client; content:"unescape|28 22|"; content:!"|29|"; within:100; content:"|22| +|0a|"; within:80; content:"|22| +|0a|"; within:80; content:"|22| "; within:80; content:"|22| +|0a|"; within:80; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:shellcode-detect; sid:2012196; rev:4; metadata:created_at 2011_01_17, updated_at 2019_09_27;)

# 2012196
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape Encoded Content With Split String Obfuscation"; flow:established,to_client; content:"unescape|28 22|"; content:!"|29|"; within:100; content:"|22| +|0a|"; within:80; content:"|22| +|0a|"; within:80; content:"|22| "; within:80; content:"|22| +|0a|"; within:80; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:shellcode-detect; sid:2012196; rev:4; metadata:created_at 2011_01_17, updated_at 2019_09_27;)
` 

Name : **Possible Unescape Encoded Content With Split String Obfuscation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html

CVE reference : Not defined

Creation date : 2011-01-17

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape Encoded Content With Split String Obfuscation 2"; flow:established,to_client; content:"unescape|28 27|"; content:!"|29|"; within:100; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:shellcode-detect; sid:2012197; rev:5; metadata:created_at 2011_01_17, updated_at 2019_09_27;)

# 2012197
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Unescape Encoded Content With Split String Obfuscation 2"; flow:established,to_client; content:"unescape|28 27|"; content:!"|29|"; within:100; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; content:"|27| +|0a|"; within:80; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:shellcode-detect; sid:2012197; rev:5; metadata:created_at 2011_01_17, updated_at 2019_09_27;)
` 

Name : **Possible Unescape Encoded Content With Split String Obfuscation 2** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html

CVE reference : Not defined

Creation date : 2011-01-17

Last modified date : 2019-09-27

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Encoded %90 NOP SLED"; flow:established,to_client; content:"%90%90%90%90"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012112; rev:5; metadata:created_at 2010_12_28, updated_at 2019_09_27;)

# 2012112
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible Encoded %90 NOP SLED"; flow:established,to_client; content:"%90%90%90%90"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012112; rev:5; metadata:created_at 2010_12_28, updated_at 2019_09_27;)
` 

Name : **Possible Encoded %90 NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html|url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html

CVE reference : Not defined

Creation date : 2010-12-28

Last modified date : 2019-09-27

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-8 %u90 NOP SLED"; flow:established,to_client; content:"%u90%u90"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012110; rev:4; metadata:created_at 2010_12_28, updated_at 2019_09_27;)

# 2012110
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-8 %u90 NOP SLED"; flow:established,to_client; content:"%u90%u90"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012110; rev:4; metadata:created_at 2010_12_28, updated_at 2019_09_27;)
` 

Name : **Possible UTF-8 %u90 NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html|url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html

CVE reference : Not defined

Creation date : 2010-12-28

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0a0a%u0a0a UTF-16 Heap Spray String"; flow:established,to_client; content:"%u0a0a%u0a0a"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012254; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012254
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0a0a%u0a0a UTF-16 Heap Spray String"; flow:established,to_client; content:"%u0a0a%u0a0a"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012254; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common %u0a0a%u0a0a UTF-16 Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0a%u0a%u0a%u0a UTF-8 Heap Spray String"; flow:established,to_client; content:"%u0a%u0a%u0a%u0a"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012255; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012255
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0a%u0a%u0a%u0a UTF-8 Heap Spray String"; flow:established,to_client; content:"%u0a%u0a%u0a%u0a"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012255; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common %u0a%u0a%u0a%u0a UTF-8 Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %0c%0c%0c%0c Heap Spray String"; flow:established,to_client; content:"%0c%0c%0c%0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012257; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012257
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %0c%0c%0c%0c Heap Spray String"; flow:established,to_client; content:"%0c%0c%0c%0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012257; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common %0c%0c%0c%0c Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0c0c%u0c0c UTF-16 Heap Spray String"; flow:established,to_client; content:"%u0c0c%u0c0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012258; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012258
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0c0c%u0c0c UTF-16 Heap Spray String"; flow:established,to_client; content:"%u0c0c%u0c0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012258; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common %u0c0c%u0c0c UTF-16 Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0c%u0c%u0c%u0c UTF-8 Heap Spray String"; flow:established,to_client; content:"%u0c%u0c%u0c%u0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012259; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012259
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common %u0c%u0c%u0c%u0c UTF-8 Heap Spray String"; flow:established,to_client; content:"%u0c%u0c%u0c%u0c"; nocase; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2012259; rev:4; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common %u0c%u0c%u0c%u0c UTF-8 Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 4

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 %u9090 NOP SLED"; flow:established,to_client; content:"%u9090%u"; nocase; pcre:"/^[a-f0-9]{4}/Ri"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012111; rev:5; metadata:created_at 2010_12_28, updated_at 2019_09_27;)

# 2012111
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible UTF-16 %u9090 NOP SLED"; flow:established,to_client; content:"%u9090%u"; nocase; pcre:"/^[a-f0-9]{4}/Ri"; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; reference:url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html; classtype:shellcode-detect; sid:2012111; rev:5; metadata:created_at 2010_12_28, updated_at 2019_09_27;)
` 

Name : **Possible UTF-16 %u9090 NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,cansecwest.com/slides07/csw07-nazario.pdf|url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html|url,www.windowsecurity.com/articles/Obfuscated-Shellcode-Part1.html

CVE reference : Not defined

Creation date : 2010-12-28

Last modified date : 2019-09-27

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common 0a0a0a0a Heap Spray String"; flow:established,to_client; content:"0a0a0a0a"; nocase; metadata: former_category SHELLCODE; reference:url,www.darkreading.com/vulnerabilities---threats/heap-spraying-attackers-latest-weapon-of-choice/d/d-id/1132487; classtype:shellcode-detect; sid:2012252; rev:5; metadata:created_at 2011_02_02, updated_at 2019_09_27;)

# 2012252
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Common 0a0a0a0a Heap Spray String"; flow:established,to_client; content:"0a0a0a0a"; nocase; metadata: former_category SHELLCODE; reference:url,www.darkreading.com/vulnerabilities---threats/heap-spraying-attackers-latest-weapon-of-choice/d/d-id/1132487; classtype:shellcode-detect; sid:2012252; rev:5; metadata:created_at 2011_02_02, updated_at 2019_09_27;)
` 

Name : **Common 0a0a0a0a Heap Spray String** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/vulnerabilities---threats/heap-spraying-attackers-latest-weapon-of-choice/d/d-id/1132487

CVE reference : Not defined

Creation date : 2011-02-02

Last modified date : 2019-09-27

Rev version : 5

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %41%41%41%41 Heap Spray Attempt"; flow:established,to_client; content:"%41%41%41%41"; fast_pattern; classtype:shellcode-detect; sid:2013145; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)

# 2013145
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %41%41%41%41 Heap Spray Attempt"; flow:established,to_client; content:"%41%41%41%41"; fast_pattern; classtype:shellcode-detect; sid:2013145; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)
` 

Name : **Possible %41%41%41%41 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-30

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u41%u41%u41%u41 UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"%u41%u41%u41%u41"; nocase; fast_pattern; classtype:shellcode-detect; sid:2013146; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)

# 2013146
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u41%u41%u41%u41 UTF-8 Heap Spray Attempt"; flow:established,to_client; content:"%u41%u41%u41%u41"; nocase; fast_pattern; classtype:shellcode-detect; sid:2013146; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)
` 

Name : **Possible %u41%u41%u41%u41 UTF-8 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-30

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u4141%u4141 UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"%u4141%u4141"; nocase; fast_pattern; classtype:shellcode-detect; sid:2013147; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)

# 2013147
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Possible %u4141%u4141 UTF-16 Heap Spray Attempt"; flow:established,to_client; content:"%u4141%u4141"; nocase; fast_pattern; classtype:shellcode-detect; sid:2013147; rev:3; metadata:created_at 2011_06_30, updated_at 2019_10_07;)
` 

Name : **Possible %u4141%u4141 UTF-16 Heap Spray Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-30

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 41414141"; flow:established,to_client; content:"|5C 5C|x41|5C 5C|x41|5C 5C|x41|5C 5C|x41"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013279; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013279
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 41414141"; flow:established,to_client; content:"|5C 5C|x41|5C 5C|x41|5C 5C|x41|5C 5C|x41"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013279; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript Heap Spray 41414141** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript NOP SLED"; flow:established,to_client; content:"|5C 5C|x90|5C 5C|x90|5C 5C|x90|5C 5C|x90"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013278; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013278
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript NOP SLED"; flow:established,to_client; content:"|5C 5C|x90|5C 5C|x90|5C 5C|x90|5C 5C|x90"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013278; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0d0d0d0d"; flow:established,to_client; content:"|5C 5C|x0d|5C 5C|x0d|5C 5C|x0d|5C 5C|x0d"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013277; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013277
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0d0d0d0d"; flow:established,to_client; content:"|5C 5C|x0d|5C 5C|x0d|5C 5C|x0d|5C 5C|x0d"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013277; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript Heap Spray 0d0d0d0d** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0c0c0c0c"; flow:established,to_client; content:"|5C 5C|x0c|5C 5C|x0c|5C 5C|x0c|5C 5C|x0c"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013276; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013276
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0c0c0c0c"; flow:established,to_client; content:"|5C 5C|x0c|5C 5C|x0c|5C 5C|x0c|5C 5C|x0c"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013276; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript Heap Spray 0c0c0c0c** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0b0b0b0b"; flow:established,to_client; content:"|5C 5C|x0b|5C 5C|x0b|5C 5C|x0b|5C 5C|x0b"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013275; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013275
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0b0b0b0b"; flow:established,to_client; content:"|5C 5C|x0b|5C 5C|x0b|5C 5C|x0b|5C 5C|x0b"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013275; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript Heap Spray 0b0b0b0b** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0a0a0a0a"; flow:established,to_client; content:"|5C 5C|x0a|5C 5C|x0a|5C 5C|x0a|5C 5C|x0a"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013274; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013274
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Double BackSlash Hex Obfuscated JavaScript Heap Spray 0a0a0a0a"; flow:established,to_client; content:"|5C 5C|x0a|5C 5C|x0a|5C 5C|x0a|5C 5C|x0a"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013274; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Double BackSlash Hex Obfuscated JavaScript Heap Spray 0a0a0a0a** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript NOP SLED"; flow:established,to_client; content:"|5C|x90|5C|x90|5C|x90|5C|x90"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013271; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013271
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript NOP SLED"; flow:established,to_client; content:"|5C|x90|5C|x90|5C|x90|5C|x90"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013271; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Hex Obfuscated JavaScript NOP SLED** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0d0d0d0d"; flow:established,to_client; content:"|5C|x0d|5C|x0d|5C|x0d|5C|x0d"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013270; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013270
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0d0d0d0d"; flow:established,to_client; content:"|5C|x0d|5C|x0d|5C|x0d|5C|x0d"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013270; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Hex Obfuscated JavaScript Heap Spray 0d0d0d0d** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0c0c0c0c"; flow:established,to_client; content:"|5C|x0c|5C|x0c|5C|x0c|5C|x0c"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013269; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)

# 2013269
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Hex Obfuscated JavaScript Heap Spray 0c0c0c0c"; flow:established,to_client; content:"|5C|x0c|5C|x0c|5C|x0c|5C|x0c"; nocase; fast_pattern; reference:url,www.darkreading.com/security/vulnerabilities/221901428/index.html; classtype:shellcode-detect; sid:2013269; rev:3; metadata:created_at 2011_07_14, updated_at 2019_10_07;)
` 

Name : **Hex Obfuscated JavaScript Heap Spray 0c0c0c0c** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : url,www.darkreading.com/security/vulnerabilities/221901428/index.html

CVE reference : Not defined

Creation date : 2011-07-14

Last modified date : 2019-10-07

Rev version : 3

Category : SHELLCODE

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SHELLCODE MSSQL shellcode attempt"; flow:to_server,established; content:"9 |D0 00 92 01 C2 00|R|00|U|00|9 |EC 00|"; fast_pattern; classtype:shellcode-detect; sid:2100691; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2100691
`alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"GPL SHELLCODE MSSQL shellcode attempt"; flow:to_server,established; content:"9 |D0 00 92 01 C2 00|R|00|U|00|9 |EC 00|"; fast_pattern; classtype:shellcode-detect; sid:2100691; rev:8; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **MSSQL shellcode attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 8

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0xEB0C NOOP"; content:"|EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C|"; fast_pattern; classtype:shellcode-detect; sid:2101424; rev:9; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101424
`alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"GPL SHELLCODE x86 0xEB0C NOOP"; content:"|EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C EB 0C|"; fast_pattern; classtype:shellcode-detect; sid:2101424; rev:9; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **x86 0xEB0C NOOP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : shellcode-detect

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 9

Category : SHELLCODE

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Polymorphic Flush IPTables Shellcode"; content:"|6a 52 58 99 52 66 68 2d 46 54 5b 52 48 b9 69 70 74 61 62 6c 65 73 51 d0 e0 28 c8 48 b9 2f 2f 73 62 69 6e 2f 2f 51 54 5f 52 53 57 54 5e 0f 05|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,a41l4.blogspot.ca/2017/03/polyflushiptables1434.html; classtype:shellcode-detect; sid:2024057; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_15, performance_impact Low, updated_at 2019_10_07;)

# 2024057
`alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Polymorphic Flush IPTables Shellcode"; content:"|6a 52 58 99 52 66 68 2d 46 54 5b 52 48 b9 69 70 74 61 62 6c 65 73 51 d0 e0 28 c8 48 b9 2f 2f 73 62 69 6e 2f 2f 51 54 5f 52 53 57 54 5e 0f 05|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,a41l4.blogspot.ca/2017/03/polyflushiptables1434.html; classtype:shellcode-detect; sid:2024057; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_15, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Linux/x86-64 - Polymorphic Flush IPTables Shellcode** 

Attack target : Client_and_Server

Description : This signature matches the Shellcode that will flush Iptables on Linux.

Tags : Not defined

Affected products : Linux

Alert Classtype : shellcode-detect

URL reference : url,a41l4.blogspot.ca/2017/03/polyflushiptables1434.html

CVE reference : Not defined

Creation date : 2017-03-15

Last modified date : 2019-10-07

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Polymorphic Setuid(0) & Execve(/bin/sh) Shellcode"; content:"|31 ff 57 6a 69 58 48 bb 5e c4 d2 dc 5e 5e e6 d0 0f 05 48 d1 cb b0 3b 53 87 f7 54 99 5f 0f 05|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,a41l4.blogspot.ca/2017/03/polysetuidexecve1434.html; classtype:shellcode-detect; sid:2024058; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_15, performance_impact Low, updated_at 2019_10_07;)

# 2024058
`alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Polymorphic Setuid(0) & Execve(/bin/sh) Shellcode"; content:"|31 ff 57 6a 69 58 48 bb 5e c4 d2 dc 5e 5e e6 d0 0f 05 48 d1 cb b0 3b 53 87 f7 54 99 5f 0f 05|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,a41l4.blogspot.ca/2017/03/polysetuidexecve1434.html; classtype:shellcode-detect; sid:2024058; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_15, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Linux/x86-64 - Polymorphic Setuid(0) & Execve(/bin/sh) Shellcode** 

Attack target : Client_and_Server

Description : This signature will match the Shellcode that will setuid(0) and then execute /bin/sh

Tags : Not defined

Affected products : Linux

Alert Classtype : shellcode-detect

URL reference : url,a41l4.blogspot.ca/2017/03/polysetuidexecve1434.html

CVE reference : Not defined

Creation date : 2017-03-15

Last modified date : 2019-10-07

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low



alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Reverse Shell Shellcode"; content:"|6a 02 6a 2a 6a 10 6a 29 6a 01 6a 02|"; content:"|48 bf 2f 2f 62 69 6e 2f 73 68|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,exploit-db.com/exploits/41477/; classtype:shellcode-detect; sid:2024065; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_16, performance_impact Low, updated_at 2019_10_07;)

# 2024065
`alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SHELLCODE Linux/x86-64 - Reverse Shell Shellcode"; content:"|6a 02 6a 2a 6a 10 6a 29 6a 01 6a 02|"; content:"|48 bf 2f 2f 62 69 6e 2f 73 68|"; fast_pattern; metadata: former_category SHELLCODE; reference:url,exploit-db.com/exploits/41477/; classtype:shellcode-detect; sid:2024065; rev:2; metadata:affected_product Linux, attack_target Client_and_Server, deployment Perimeter, signature_severity Critical, created_at 2017_03_16, performance_impact Low, updated_at 2019_10_07;)
` 

Name : **Linux/x86-64 - Reverse Shell Shellcode** 

Attack target : Client_and_Server

Description : This signature will match a shellcode that opens a reverse shell at the target.

Tags : Not defined

Affected products : Linux

Alert Classtype : shellcode-detect

URL reference : url,exploit-db.com/exploits/41477/

CVE reference : Not defined

Creation date : 2017-03-16

Last modified date : 2019-10-07

Rev version : 2

Category : SHELLCODE

Severity : Critical

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Low


