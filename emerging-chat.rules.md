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



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Facebook Chat using XMPP"; flow:to_server,established; content:"chat.facebook.com"; nocase; content:"jabber|3A|client"; nocase; distance:9; within:13; threshold: type limit, track by_src, count 1, seconds 60; reference:url,www.facebook.com/sitetour/chat.php; reference:url,doc.emergingthreats.net/2010819; classtype:policy-violation; sid:2010819; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2010819
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Facebook Chat using XMPP"; flow:to_server,established; content:"chat.facebook.com"; nocase; content:"jabber|3A|client"; nocase; distance:9; within:13; threshold: type limit, track by_src, count 1, seconds 60; reference:url,www.facebook.com/sitetour/chat.php; reference:url,doc.emergingthreats.net/2010819; classtype:policy-violation; sid:2010819; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Facebook Chat using XMPP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.facebook.com/sitetour/chat.php|url,doc.emergingthreats.net/2010819

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Client Login Packet"; flowbits:isset,ET.gadu.welcome; flow:established,to_server; dsize:<50; content:"|15 00 00 00|"; depth:4; flowbits:set,ET.gadu.loginsent; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008298; classtype:policy-violation; sid:2008298; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008298
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Client Login Packet"; flowbits:isset,ET.gadu.welcome; flow:established,to_server; dsize:<50; content:"|15 00 00 00|"; depth:4; flowbits:set,ET.gadu.loginsent; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008298; classtype:policy-violation; sid:2008298; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Client Login Packet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008298

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Login Failed Packet"; flowbits:isset,ET.gadu.loginsent; flow:established,from_server; dsize:8; content:"|09 00 00 00 00 00 00 00|"; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008300; classtype:policy-violation; sid:2008300; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008300
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Login Failed Packet"; flowbits:isset,ET.gadu.loginsent; flow:established,from_server; dsize:8; content:"|09 00 00 00 00 00 00 00|"; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008300; classtype:policy-violation; sid:2008300; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Server Login Failed Packet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008300

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Server Available Status Packet"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|02 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008301; classtype:policy-violation; sid:2008301; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008301
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Server Available Status Packet"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|02 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008301; classtype:policy-violation; sid:2008301; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Server Available Status Packet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008301

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Send Message"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|0b 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008302; classtype:policy-violation; sid:2008302; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008302
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Send Message"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|0b 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008302; classtype:policy-violation; sid:2008302; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Send Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008302

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Receive Message"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|0a 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008303; classtype:policy-violation; sid:2008303; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008303
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Receive Message"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|0a 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008303; classtype:policy-violation; sid:2008303; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Receive Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008303

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Keepalive PING"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|08 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008304; classtype:policy-violation; sid:2008304; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008304
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat Keepalive PING"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|08 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008304; classtype:policy-violation; sid:2008304; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Keepalive PING** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008304

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Keepalive PONG"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|07 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008305; classtype:policy-violation; sid:2008305; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008305
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Keepalive PONG"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|07 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008305; classtype:policy-violation; sid:2008305; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Keepalive PONG** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008305

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat File Send Request"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|01 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008306; classtype:policy-violation; sid:2008306; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008306
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat File Send Request"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|01 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008306; classtype:policy-violation; sid:2008306; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat File Send Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008306

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat File Send Details"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|03 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008307; classtype:policy-violation; sid:2008307; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008307
`alert tcp $HOME_NET any -> $EXTERNAL_NET 8074 (msg:"ET CHAT GaduGadu Chat File Send Details"; flowbits:isset,ET.gadu.loggedin; flow:established,to_server; content:"|03 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008307; classtype:policy-violation; sid:2008307; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat File Send Details** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008307

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat File Send Accept"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|06 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008308; classtype:policy-violation; sid:2008308; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008308
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat File Send Accept"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|06 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008308; classtype:policy-violation; sid:2008308; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat File Send Accept** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008308

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat File Send Begin"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|03 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008309; classtype:policy-violation; sid:2008309; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008309
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat File Send Begin"; flowbits:isset,ET.gadu.loggedin; flow:established,from_server; content:"|03 00 00 00|"; depth:4; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008309; classtype:policy-violation; sid:2008309; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat File Send Begin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008309

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Invisible"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|001900130005|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001801; classtype:policy-violation; sid:2001801; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001801
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Invisible"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|001900130005|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001801; classtype:policy-violation; sid:2001801; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICQ Status Invisible** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001801

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Change (1)"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|000E00010011|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001802; classtype:policy-violation; sid:2001802; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001802
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Change (1)"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|000E00010011|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001802; classtype:policy-violation; sid:2001802; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICQ Status Change (1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001802

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Change (2)"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|00120001001E|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001803; classtype:policy-violation; sid:2001803; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001803
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Status Change (2)"; flow: from_client,established; content:"|2A02|"; depth: 2; content:"|00120001001E|"; offset: 4; depth: 6; reference:url,doc.emergingthreats.net/2001803; classtype:policy-violation; sid:2001803; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICQ Status Change (2)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001803

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Login"; flow: from_client,established; content:"|2A01|"; depth: 2; content:"|00010001|"; offset: 8; depth: 4; reference:url,doc.emergingthreats.net/2001804; classtype:policy-violation; sid:2001804; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001804
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:"ET CHAT ICQ Login"; flow: from_client,established; content:"|2A01|"; depth: 2; content:"|00010001|"; offset: 8; depth: 4; reference:url,doc.emergingthreats.net/2001804; classtype:policy-violation; sid:2001804; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICQ Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001804

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT ICQ Message"; flow: established; content:"|2A02|"; depth: 2; content:"|000400060000|"; offset: 6; depth: 6; reference:url,doc.emergingthreats.net/2001805; classtype:policy-violation; sid:2001805; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001805
`alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT ICQ Message"; flow: established; content:"|2A02|"; depth: 2; content:"|000400060000|"; offset: 6; depth: 6; reference:url,doc.emergingthreats.net/2001805; classtype:policy-violation; sid:2001805; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ICQ Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001805

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Google Talk (Jabber) Client Login"; flow:established,to_server; content:"gmail.com"; nocase; content:"jabber"; nocase; distance:9; within:6; reference:url,talk.google.com; reference:url,www.xmpp.org; reference:url,doc.emergingthreats.net/2002327; classtype:policy-violation; sid:2002327; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002327
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Google Talk (Jabber) Client Login"; flow:established,to_server; content:"gmail.com"; nocase; content:"jabber"; nocase; distance:9; within:6; reference:url,talk.google.com; reference:url,www.xmpp.org; reference:url,doc.emergingthreats.net/2002327; classtype:policy-violation; sid:2002327; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Google Talk (Jabber) Client Login** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,talk.google.com|url,www.xmpp.org|url,doc.emergingthreats.net/2002327

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer request"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; distance: 0; content:"text/x-msmsgsinvite"; nocase; distance: 0; content:"Application-Name|3A|"; content:"File Transfer"; nocase; distance: 0; reference:url,doc.emergingthreats.net/2001241; classtype:policy-violation; sid:2001241; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001241
`#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer request"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; distance: 0; content:"text/x-msmsgsinvite"; nocase; distance: 0; content:"Application-Name|3A|"; content:"File Transfer"; nocase; distance: 0; reference:url,doc.emergingthreats.net/2001241; classtype:policy-violation; sid:2001241; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSN file transfer request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001241

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer accept"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; content:"text/x-msmsgsinvite"; distance: 0; content:"Invitation-Command|3A|"; content:"ACCEPT"; distance: 1; reference:url,doc.emergingthreats.net/2001242; classtype:policy-violation; sid:2001242; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001242
`#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer accept"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; content:"text/x-msmsgsinvite"; distance: 0; content:"Invitation-Command|3A|"; content:"ACCEPT"; distance: 1; reference:url,doc.emergingthreats.net/2001242; classtype:policy-violation; sid:2001242; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSN file transfer accept** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001242

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer reject"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; content:"text/x-msmsgsinvite"; distance: 0; content:"Invitation-Command|3A|"; content:"CANCEL"; distance: 0; content:"Cancel-Code|3A|"; nocase; content:"REJECT"; nocase; distance: 0; reference:url,doc.emergingthreats.net/2001243; classtype:policy-violation; sid:2001243; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001243
`#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT MSN file transfer reject"; flow: established; content:"MSG "; depth: 4; content:"Content-Type|3A|"; nocase; content:"text/x-msmsgsinvite"; distance: 0; content:"Invitation-Command|3A|"; content:"CANCEL"; distance: 0; content:"Cancel-Code|3A|"; nocase; content:"REJECT"; nocase; distance: 0; reference:url,doc.emergingthreats.net/2001243; classtype:policy-violation; sid:2001243; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSN file transfer reject** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001243

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT MSN status change"; flow:established,to_server; content:"CHG "; depth:55; reference:url,doc.emergingthreats.net/2002192; classtype:policy-violation; sid:2002192; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002192
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT MSN status change"; flow:established,to_server; content:"CHG "; depth:55; reference:url,doc.emergingthreats.net/2002192; classtype:policy-violation; sid:2002192; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSN status change** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2002192

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM voicechat"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00|J"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001254; classtype:policy-violation; sid:2001254; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001254
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM voicechat"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00|J"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001254; classtype:policy-violation; sid:2001254; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM voicechat** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001254

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM ping"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 12|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001255; classtype:policy-violation; sid:2001255; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001255
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM ping"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 12|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001255; classtype:policy-violation; sid:2001255; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM ping** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001255

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference invitation"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 18|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001256; classtype:policy-violation; sid:2001256; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001256
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference invitation"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 18|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001256; classtype:policy-violation; sid:2001256; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference invitation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001256

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference logon success"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 19|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001257; classtype:policy-violation; sid:2001257; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001257
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference logon success"; flow: from_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 19|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001257; classtype:policy-violation; sid:2001257; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference logon success** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001257

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference message"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 1D|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001258; classtype:policy-violation; sid:2001258; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001258
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference message"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00 1D|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001258; classtype:policy-violation; sid:2001258; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001258

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM Unavailable Status"; flow: to_server,established; content:"|59 47 00 0b 00 00 00 00 00 12 00 00 00 00|"; depth: 55; reference:url,doc.emergingthreats.net/2001427; classtype:policy-violation; sid:2001427; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001427
`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM Unavailable Status"; flow: to_server,established; content:"|59 47 00 0b 00 00 00 00 00 12 00 00 00 00|"; depth: 55; reference:url,doc.emergingthreats.net/2001427; classtype:policy-violation; sid:2001427; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM Unavailable Status** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001427

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM message"; flow: established; content:"YMSG"; depth: 4; reference:url,doc.emergingthreats.net/2001260; classtype:policy-violation; sid:2001260; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001260
`#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM message"; flow: established; content:"YMSG"; depth: 4; reference:url,doc.emergingthreats.net/2001260; classtype:policy-violation; sid:2001260; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001260

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference offer invitation"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00|P"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001262; classtype:policy-violation; sid:2001262; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001262
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference offer invitation"; flow: to_server,established; content:"YMSG"; nocase; depth: 4; content:"|00|P"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001262; classtype:policy-violation; sid:2001262; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference offer invitation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001262

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference request"; flow: to_server,established; content:"<R"; depth: 2; pcre:"/^\x3c(REQIMG|RVWCFG)\x3e/ism"; reference:url,doc.emergingthreats.net/2001263; classtype:policy-violation; sid:2001263; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001263
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM conference request"; flow: to_server,established; content:"<R"; depth: 2; pcre:"/^\x3c(REQIMG|RVWCFG)\x3e/ism"; reference:url,doc.emergingthreats.net/2001263; classtype:policy-violation; sid:2001263; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001263

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference watch"; flow: from_server,established; content:"|0D 00 05 00|"; depth: 4; reference:url,doc.emergingthreats.net/2001264; classtype:policy-violation; sid:2001264; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001264
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT Yahoo IM conference watch"; flow: from_server,established; content:"|0D 00 05 00|"; depth: 4; reference:url,doc.emergingthreats.net/2001264; classtype:policy-violation; sid:2001264; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM conference watch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001264

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT IRC authorization message"; flow: established; content:"NOTICE AUTH"; content:"Looking up your hostname..."; nocase; reference:url,doc.emergingthreats.net/2000355; classtype:misc-activity; sid:2000355; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2000355
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CHAT IRC authorization message"; flow: established; content:"NOTICE AUTH"; content:"Looking up your hostname..."; nocase; reference:url,doc.emergingthreats.net/2000355; classtype:misc-activity; sid:2000355; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC authorization message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2000355

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Known SSL traffic on port 5222 (Jabber) being excluded from SSL Alerts"; flow:established,to_server; flowbits:noalert; flowbits:set,BS.SSL.Known.Port; reference:url,doc.emergingthreats.net/2003031; classtype:not-suspicious; sid:2003031; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003031
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Known SSL traffic on port 5222 (Jabber) being excluded from SSL Alerts"; flow:established,to_server; flowbits:noalert; flowbits:set,BS.SSL.Known.Port; reference:url,doc.emergingthreats.net/2003031; classtype:not-suspicious; sid:2003031; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Known SSL traffic on port 5222 (Jabber) being excluded from SSL Alerts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2003031

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 5223 (msg:"ET CHAT Known SSL traffic on port 5223 (Jabber) being excluded from SSL Alerts"; flow:established,to_server; flowbits:noalert; flowbits:set,BS.SSL.Known.Port; reference:url,doc.emergingthreats.net/2003032; classtype:not-suspicious; sid:2003032; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003032
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 5223 (msg:"ET CHAT Known SSL traffic on port 5223 (Jabber) being excluded from SSL Alerts"; flow:established,to_server; flowbits:noalert; flowbits:set,BS.SSL.Known.Port; reference:url,doc.emergingthreats.net/2003032; classtype:not-suspicious; sid:2003032; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Known SSL traffic on port 5223 (Jabber) being excluded from SSL Alerts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,doc.emergingthreats.net/2003032

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Google IM traffic Jabber client sign-on"; flow:to_server; content:"gmail.com"; nocase; content:"jabber.org"; nocase; content:"version="; reference:url,www.google.com/talk; reference:url,doc.emergingthreats.net/2002334; classtype:policy-violation; sid:2002334; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002334
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"ET CHAT Google IM traffic Jabber client sign-on"; flow:to_server; content:"gmail.com"; nocase; content:"jabber.org"; nocase; content:"version="; reference:url,www.google.com/talk; reference:url,doc.emergingthreats.net/2002334; classtype:policy-violation; sid:2002334; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Google IM traffic Jabber client sign-on** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk|url,doc.emergingthreats.net/2002334

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"ET CHAT Possible MSN Messenger File Transfer"; flow:established,from_client; content:"x-msnmsgrp2p"; nocase; content:"appid|3a|"; nocase; pcre:"/appid\x3a\s+2/i"; reference:url,www.hypothetic.org/docs/msn/client/file_transfer.php; reference:url,doc.emergingthreats.net/2008289; classtype:policy-violation; sid:2008289; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008289
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"ET CHAT Possible MSN Messenger File Transfer"; flow:established,from_client; content:"x-msnmsgrp2p"; nocase; content:"appid|3a|"; nocase; pcre:"/appid\x3a\s+2/i"; reference:url,www.hypothetic.org/docs/msn/client/file_transfer.php; reference:url,doc.emergingthreats.net/2008289; classtype:policy-violation; sid:2008289; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Possible MSN Messenger File Transfer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.hypothetic.org/docs/msn/client/file_transfer.php|url,doc.emergingthreats.net/2008289

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN user search"; flow:to_server,established; content:"CAL "; depth:4; nocase; classtype:policy-violation; sid:2101990; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101990
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN user search"; flow:to_server,established; content:"CAL "; depth:4; nocase; classtype:policy-violation; sid:2101990; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSN user search** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 2

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN login attempt"; flow:to_server,established; content:"USR "; depth:4; nocase; content:" TWN "; distance:1; nocase; threshold:type limit, track by_src, count 1, seconds 60; classtype:policy-violation; sid:2101991; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101991
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN login attempt"; flow:to_server,established; content:"USR "; depth:4; nocase; content:" TWN "; distance:1; nocase; threshold:type limit, track by_src, count 1, seconds 60; classtype:policy-violation; sid:2101991; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSN login attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN outbound file transfer request"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; nocase; content:"INVITE"; distance:0; nocase; classtype:policy-violation; sid:2101986; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101986
`alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN outbound file transfer request"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; nocase; content:"INVITE"; distance:0; nocase; classtype:policy-violation; sid:2101986; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSN outbound file transfer request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 1863 -> $HOME_NET any (msg:"GPL CHAT MSN outbound file transfer accept"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; distance:0; nocase; content:"MSNSLP/1.0 200 OK"; distance:0; nocase; classtype:policy-violation; sid:2101988; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101988
`alert tcp $EXTERNAL_NET 1863 -> $HOME_NET any (msg:"GPL CHAT MSN outbound file transfer accept"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; distance:0; nocase; content:"MSNSLP/1.0 200 OK"; distance:0; nocase; classtype:policy-violation; sid:2101988; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSN outbound file transfer accept** 

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

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 1863 -> $HOME_NET any (msg:"GPL CHAT MSN outbound file transfer rejected"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; distance:0; nocase; content:"MSNSLP/1.0 603 Decline"; distance:0; nocase; classtype:policy-violation; sid:2101989; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101989
`alert tcp $EXTERNAL_NET 1863 -> $HOME_NET any (msg:"GPL CHAT MSN outbound file transfer rejected"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A| application/x-msnmsgrp2p"; distance:0; nocase; content:"MSNSLP/1.0 603 Decline"; distance:0; nocase; classtype:policy-violation; sid:2101989; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **MSN outbound file transfer rejected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $AIM_SERVERS any -> $HOME_NET any (msg:"GPL CHAT AIM receive message"; flow:to_client; content:"*|02|"; depth:2; content:"|00 04 00 07|"; depth:4; offset:6; classtype:policy-violation; sid:2101633; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101633
`alert tcp $AIM_SERVERS any -> $HOME_NET any (msg:"GPL CHAT AIM receive message"; flow:to_client; content:"*|02|"; depth:2; content:"|00 04 00 07|"; depth:4; offset:6; classtype:policy-violation; sid:2101633; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AIM receive message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $AIM_SERVERS any (msg:"GPL CHAT AIM send message"; flow:to_server,established; content:"*|02|"; depth:2; content:"|00 04 00 06|"; depth:4; offset:6; classtype:policy-violation; sid:2101632; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101632
`#alert tcp $HOME_NET any -> $AIM_SERVERS any (msg:"GPL CHAT AIM send message"; flow:to_server,established; content:"*|02|"; depth:2; content:"|00 04 00 06|"; depth:4; offset:6; classtype:policy-violation; sid:2101632; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AIM send message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $AIM_SERVERS any (msg:"GPL CHAT AIM login"; flow:to_server,established; content:"*|02|"; depth:2; content:"|00 17 00 06|"; within:8; distance:4; classtype:policy-violation; sid:2101631; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101631
`alert tcp $HOME_NET any -> $AIM_SERVERS any (msg:"GPL CHAT AIM login"; flow:to_server,established; content:"*|02|"; depth:2; content:"|00 17 00 06|"; within:8; distance:4; classtype:policy-violation; sid:2101631; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **AIM login** 

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

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any <> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN message"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A|"; nocase; content:"text/plain"; distance:1; metadata: former_category CHAT; classtype:policy-violation; sid:2100540; rev:12; metadata:created_at 2010_09_23, updated_at 2019_05_21;)

# 2100540
`#alert tcp $HOME_NET any <> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN message"; flow:established; content:"MSG "; depth:4; content:"Content-Type|3A|"; nocase; content:"text/plain"; distance:1; metadata: former_category CHAT; classtype:policy-violation; sid:2100540; rev:12; metadata:created_at 2010_09_23, updated_at 2019_05_21;)
` 

Name : **MSN message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-05-21

Rev version : 12

Category : DELETED

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC DCC chat request"; flow:to_server,established; content:"PRIVMSG "; depth:8; nocase; content:" |3A|.DCC CHAT chat"; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101640; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101640
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC DCC chat request"; flow:to_server,established; content:"PRIVMSG "; depth:8; nocase; content:" |3A|.DCC CHAT chat"; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101640; rev:10; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IRC DCC chat request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 10

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC DCC file transfer request"; flow:to_server,established; content:"PRIVMSG "; depth:8; nocase; content:" |3A|.DCC SEND"; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101639; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2101639
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC DCC file transfer request"; flow:to_server,established; content:"PRIVMSG "; depth:8; nocase; content:" |3A|.DCC SEND"; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101639; rev:11; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IRC DCC file transfer request** 

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

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC NICK command"; flow:to_server,established; content:"NICK|20|"; nocase; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002024; classtype:misc-activity; sid:2002024; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002024
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC NICK command"; flow:to_server,established; content:"NICK|20|"; nocase; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002024; classtype:misc-activity; sid:2002024; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC NICK command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002024

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 19

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC JOIN command"; flow:to_server,established; content:"JOIN|2023|"; nocase; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002025; classtype:misc-activity; sid:2002025; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002025
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC JOIN command"; flow:to_server,established; content:"JOIN|2023|"; nocase; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002025; classtype:misc-activity; sid:2002025; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC JOIN command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002025

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 19

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC USER command"; flow:to_server,established; content:"USER|20|"; nocase; content:"|203a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002023; classtype:misc-activity; sid:2002023; rev:16; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002023
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC USER command"; flow:to_server,established; content:"USER|20|"; nocase; content:"|203a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002023; classtype:misc-activity; sid:2002023; rev:16; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC USER command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002023

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 16

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC PRIVMSG command"; flow:established,to_server; content:"PRIVMSG|20|"; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002026; classtype:misc-activity; sid:2002026; rev:21; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002026
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC PRIVMSG command"; flow:established,to_server; content:"PRIVMSG|20|"; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002026; classtype:misc-activity; sid:2002026; rev:21; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC PRIVMSG command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002026

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 21

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any 6666:7000 -> any any (msg:"ET CHAT IRC PING command"; flow:from_server,established; content:"PING|20|"; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002027; classtype:misc-activity; sid:2002027; rev:16; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002027
`alert tcp any 6666:7000 -> any any (msg:"ET CHAT IRC PING command"; flow:from_server,established; content:"PING|20|"; flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002027; classtype:misc-activity; sid:2002027; rev:16; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC PING command** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002027

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 16

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM successful chat join"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 98|"; depth:2; offset:10; classtype:policy-violation; sid:2102458; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102458
`alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM successful chat join"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 98|"; depth:2; offset:10; classtype:policy-violation; sid:2102458; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM successful chat join** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5100 (msg:"GPL CHAT Yahoo IM conference request"; flow:to_server,established; content:"<R"; depth:2; pcre:"/^\x3c(REQIMG|RVWCFG)\x3e/ism"; classtype:policy-violation; sid:2102460; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102460
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5100 (msg:"GPL CHAT Yahoo IM conference request"; flow:to_server,established; content:"<R"; depth:2; pcre:"/^\x3c(REQIMG|RVWCFG)\x3e/ism"; classtype:policy-violation; sid:2102460; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM ping"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00 12|"; depth:2; offset:10; classtype:policy-violation; sid:2102452; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102452
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM ping"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00 12|"; depth:2; offset:10; classtype:policy-violation; sid:2102452; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM ping** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM conference offer invitation"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00|P"; depth:2; offset:10; classtype:policy-violation; sid:2102459; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102459
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM conference offer invitation"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00|P"; depth:2; offset:10; classtype:policy-violation; sid:2102459; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference offer invitation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM conference message"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00 1D|"; depth:2; offset:10; classtype:policy-violation; sid:2102455; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102455
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5050 (msg:"GPL CHAT Yahoo IM conference message"; flow:to_server,established; content:"YMSG"; depth:4; nocase; content:"|00 1D|"; depth:2; offset:10; classtype:policy-violation; sid:2102455; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5100 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference watch"; flow:from_server,established; content:"|0D 00 05 00|"; depth:4; classtype:policy-violation; sid:2102461; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102461
`alert tcp $EXTERNAL_NET 5100 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference watch"; flow:from_server,established; content:"|0D 00 05 00|"; depth:4; classtype:policy-violation; sid:2102461; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference watch** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo Messenger File Transfer Receive Request"; flow:established; content:"YMSG"; depth:4; content:"|00|M"; depth:2; offset:10; classtype:policy-violation; sid:2102456; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102456
`alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo Messenger File Transfer Receive Request"; flow:established; content:"YMSG"; depth:4; content:"|00|M"; depth:2; offset:10; classtype:policy-violation; sid:2102456; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo Messenger File Transfer Receive Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM voicechat"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00|J"; depth:2; offset:10; classtype:policy-violation; sid:2102451; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102451
`alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM voicechat"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00|J"; depth:2; offset:10; classtype:policy-violation; sid:2102451; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM voicechat** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference logon success"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 19|"; depth:2; offset:10; classtype:policy-violation; sid:2102454; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102454
`alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference logon success"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 19|"; depth:2; offset:10; classtype:policy-violation; sid:2102454; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference logon success** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference invitation"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 18|"; depth:2; offset:10; classtype:policy-violation; sid:2102453; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2102453
`alert tcp $EXTERNAL_NET 5050 -> $HOME_NET any (msg:"GPL CHAT Yahoo IM conference invitation"; flow:from_server,established; content:"YMSG"; depth:4; nocase; content:"|00 18|"; depth:2; offset:10; classtype:policy-violation; sid:2102453; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Yahoo IM conference invitation** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Skype User-Agent detected"; flow:to_server,established; content:"Skype"; http_user_agent; reference:url,doc.emergingthreats.net/2002157; classtype:policy-violation; sid:2002157; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002157
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Skype User-Agent detected"; flow:to_server,established; content:"Skype"; http_user_agent; reference:url,doc.emergingthreats.net/2002157; classtype:policy-violation; sid:2002157; rev:11; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Skype User-Agent detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2002157

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 11

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (buddy list)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/buddy_list.php"; http_uri; content:"facebook.com"; http_header; reference:url,doc.emergingthreats.net/2010785; classtype:policy-violation; sid:2010785; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2010785
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (buddy list)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/buddy_list.php"; http_uri; content:"facebook.com"; http_header; reference:url,doc.emergingthreats.net/2010785; classtype:policy-violation; sid:2010785; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Facebook Chat (buddy list)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010785

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 6

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT MSN IM Poll via HTTP"; flow: established,to_server; content:"/gateway/gateway.dll?Action=poll&SessionID="; http_uri; nocase; threshold: type limit, track by_src, count 10, seconds 3600; reference:url,doc.emergingthreats.net/2001682; classtype:policy-violation; sid:2001682; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001682
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT MSN IM Poll via HTTP"; flow: established,to_server; content:"/gateway/gateway.dll?Action=poll&SessionID="; http_uri; nocase; threshold: type limit, track by_src, count 10, seconds 3600; reference:url,doc.emergingthreats.net/2001682; classtype:policy-violation; sid:2001682; rev:10; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **MSN IM Poll via HTTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001682

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 10

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC USER Likely bot with 0 0 colon checkin"; flow:to_server,established; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; metadata: former_category CHAT; classtype:misc-activity; sid:2025066; rev:1; metadata:created_at 2013_07_12, updated_at 2017_11_28;)

# 2025066
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC USER Likely bot with 0 0 colon checkin"; flow:to_server,established; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; metadata: former_category CHAT; classtype:misc-activity; sid:2025066; rev:1; metadata:created_at 2013_07_12, updated_at 2017_11_28;)
` 

Name : **IRC USER Likely bot with 0 0 colon checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2017-11-28

Rev version : 1

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any !6666:7000 (msg:"ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin"; flow:to_server,established; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; metadata: former_category CHAT; classtype:misc-activity; sid:2025067; rev:1; metadata:created_at 2013_07_12, updated_at 2017_11_28;)

# 2025067
`alert tcp any any -> any !6666:7000 (msg:"ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin"; flow:to_server,established; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; metadata: former_category CHAT; classtype:misc-activity; sid:2025067; rev:1; metadata:created_at 2013_07_12, updated_at 2017_11_28;)
` 

Name : **IRC USER Off-port Likely bot with 0 0 colon checkin** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2013-07-12

Last modified date : 2017-11-28

Rev version : 1

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC PONG response"; flow:from_client,established; content:"PONG|20|"; depth:5;  flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002028; classtype:misc-activity; sid:2002028; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2002028
`alert tcp any any -> any 6666:7000 (msg:"ET CHAT IRC PONG response"; flow:from_client,established; content:"PONG|20|"; depth:5;  flowbits:set,is_proto_irc; reference:url,doc.emergingthreats.net/2002028; classtype:misc-activity; sid:2002028; rev:19; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **IRC PONG response** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,doc.emergingthreats.net/2002028

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 19

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Login OK Packet"; flowbits:isset,ET.gadu.loginsent; flow:established,from_server; content:"|03 00 00 00|"; depth:4; byte_jump:4,0,relative,little,post_offset -1; isdataat:!2,relative; flowbits:set,ET.gadu.loggedin; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008299; classtype:policy-violation; sid:2008299; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008299
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Login OK Packet"; flowbits:isset,ET.gadu.loginsent; flow:established,from_server; content:"|03 00 00 00|"; depth:4; byte_jump:4,0,relative,little,post_offset -1; isdataat:!2,relative; flowbits:set,ET.gadu.loggedin; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008299; classtype:policy-violation; sid:2008299; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **GaduGadu Chat Server Login OK Packet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008299

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM file transfer request"; flow: established; content:"YMSG"; nocase; depth: 4; content:"|00 dc|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001259; classtype:policy-violation; sid:2001259; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001259
`alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM file transfer request"; flow: established; content:"YMSG"; nocase; depth: 4; content:"|00 dc|"; offset: 10; depth: 2; reference:url,doc.emergingthreats.net/2001259; classtype:policy-violation; sid:2001259; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Yahoo IM file transfer request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2001259

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 33033 (msg:"ET CHAT Skype Bootstrap Node (udp)"; threshold: type both, count 5, track by_src, seconds 120; reference:url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf; reference:url,doc.emergingthreats.net/2003022; classtype:policy-violation; sid:2003022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2003022
`#alert udp $HOME_NET 1024:65535 -> $EXTERNAL_NET 33033 (msg:"ET CHAT Skype Bootstrap Node (udp)"; threshold: type both, count 5, track by_src, seconds 120; reference:url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf; reference:url,doc.emergingthreats.net/2003022; classtype:policy-violation; sid:2003022; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Skype Bootstrap Node (udp)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf|url,doc.emergingthreats.net/2003022

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outoing Message"; flow:to_server,established; content:"<message"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100233; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100233
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outoing Message"; flow:to_server,established; content:"<message"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100233; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Outoing Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outgoing Traffic"; flow:to_server,established; content:"<stream"; nocase; reference:url,www.google.com/talk/; classtype:not-suspicious; sid:2100230; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100230
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outgoing Traffic"; flow:to_server,established; content:"<stream"; nocase; reference:url,www.google.com/talk/; classtype:not-suspicious; sid:2100230; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Outgoing Traffic** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : not-suspicious

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outgoing Auth"; flow:to_server,established; content:"<auth"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100231; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100231
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Outgoing Auth"; flow:to_server,established; content:"<auth"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100231; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Outgoing Auth** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Log Out"; flow:to_server,established; content:"</stream"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100234; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100234
`#alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Jabber/Google Talk Log Out"; flow:to_server,established; content:"</stream"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100234; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Log Out** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Google Talk Startup"; flow: established,to_server; content:"google.com"; nocase; content:"jabber|3A|client"; nocase; threshold: type limit, track by_src, count 1, seconds 300; classtype:policy-violation; sid:2100877; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100877
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Google Talk Startup"; flow: established,to_server; content:"google.com"; nocase; content:"jabber|3A|client"; nocase; threshold: type limit, track by_src, count 1, seconds 300; classtype:policy-violation; sid:2100877; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Google Talk Startup** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Google Talk Logon"; flow:to_server,established; content:"<stream|3a|stream to=\"gmail.com\""; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100232; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100232
`alert tcp $HOME_NET any -> $EXTERNAL_NET 5222 (msg:"GPL CHAT Google Talk Logon"; flow:to_server,established; content:"<stream|3a|stream to=\"gmail.com\""; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100232; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Google Talk Logon** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL CHAT Google Talk Version Check"; flow: established,to_server; content:"/googletalk/google-talk-versioncheck.txt?"; http_uri; nocase; classtype:policy-violation; sid:2100876; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100876
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL CHAT Google Talk Version Check"; flow: established,to_server; content:"/googletalk/google-talk-versioncheck.txt?"; http_uri; nocase; classtype:policy-violation; sid:2100876; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Google Talk Version Check** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5222 -> $HOME_NET any (msg:"GPL CHAT Jabber/Google Talk Logon Success"; flow:to_client,established; content:"<success"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100235; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100235
`alert tcp $EXTERNAL_NET 5222 -> $HOME_NET any (msg:"GPL CHAT Jabber/Google Talk Logon Success"; flow:to_client,established; content:"<success"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100235; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Logon Success** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 5222 -> $HOME_NET any (msg:"GPL CHAT Jabber/Google Talk Incoming Message"; flow:to_client,established; content:"<message"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100236; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100236
`alert tcp $EXTERNAL_NET 5222 -> $HOME_NET any (msg:"GPL CHAT Jabber/Google Talk Incoming Message"; flow:to_client,established; content:"<message"; nocase; reference:url,www.google.com/talk/; classtype:policy-violation; sid:2100236; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Jabber/Google Talk Incoming Message** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.google.com/talk/

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Gadu-Gadu IM Login Server Request"; flow:established,to_server; content:"/appsvc/appmsg"; http_uri; nocase; content:".asp"; http_uri; nocase; content:"fmnumber="; http_uri; content:"&version="; http_uri; content:"&fmt="; http_uri; content:"appmsg.gadu-gadu."; http_host; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008295; classtype:policy-violation; sid:2008295; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2008295
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Gadu-Gadu IM Login Server Request"; flow:established,to_server; content:"/appsvc/appmsg"; http_uri; nocase; content:".asp"; http_uri; nocase; content:"fmnumber="; http_uri; content:"&version="; http_uri; content:"&fmt="; http_uri; content:"appmsg.gadu-gadu."; http_host; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008295; classtype:policy-violation; sid:2008295; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gadu-Gadu IM Login Server Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008295

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Gadu-Gadu Chat Client Checkin via HTTP"; flow:established,to_server; content:"/appsvc/appmsg"; nocase; http_uri; content:"fmnumber="; nocase; http_uri; content:"&version="; nocase; http_uri; content:"&fmt="; nocase; http_uri; content:"&lastmsg="; http_uri; nocase; reference:url,doc.emergingthreats.net/2007866; classtype:trojan-activity; sid:2007866; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2007866
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Gadu-Gadu Chat Client Checkin via HTTP"; flow:established,to_server; content:"/appsvc/appmsg"; nocase; http_uri; content:"fmnumber="; nocase; http_uri; content:"&version="; nocase; http_uri; content:"&fmt="; nocase; http_uri; content:"&lastmsg="; http_uri; nocase; reference:url,doc.emergingthreats.net/2007866; classtype:trojan-activity; sid:2007866; rev:9; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Gadu-Gadu Chat Client Checkin via HTTP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,doc.emergingthreats.net/2007866

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 9

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Welcome Packet"; flow:established,from_server; dsize:12; content:"|01 00 00 00|"; depth:4; flowbits:set,ET.gadu.welcome; metadata: former_category CHAT; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008297; classtype:policy-violation; sid:2008297; rev:5; metadata:created_at 2010_07_30, updated_at 2017_12_11;)

# 2008297
`alert tcp $EXTERNAL_NET 8074 -> $HOME_NET any (msg:"ET CHAT GaduGadu Chat Server Welcome Packet"; flow:established,from_server; dsize:12; content:"|01 00 00 00|"; depth:4; flowbits:set,ET.gadu.welcome; metadata: former_category CHAT; reference:url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html; reference:url,doc.emergingthreats.net/2008297; classtype:policy-violation; sid:2008297; rev:5; metadata:created_at 2010_07_30, updated_at 2017_12_11;)
` 

Name : **GaduGadu Chat Server Welcome Packet** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,piotr.trzcionkowski.pl/default.asp?load=/programy/pppgg_protokol.html|url,doc.emergingthreats.net/2008297

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2017-12-11

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Skype VOIP Checking Version (Startup)"; flow: to_server,established; content:"/ui/"; http_uri; nocase; content:"/getlatestversion?ver="; http_uri; nocase; reference:url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf; reference:url,doc.emergingthreats.net/2001595; classtype:policy-violation; sid:2001595; rev:11; metadata:created_at 2010_07_30, updated_at 2019_09_26;)

# 2001595
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Skype VOIP Checking Version (Startup)"; flow: to_server,established; content:"/ui/"; http_uri; nocase; content:"/getlatestversion?ver="; http_uri; nocase; reference:url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf; reference:url,doc.emergingthreats.net/2001595; classtype:policy-violation; sid:2001595; rev:11; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Skype VOIP Checking Version (Startup)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www1.cs.columbia.edu/~library/TR-repository/reports/reports-2004/cucs-039-04.pdf|url,doc.emergingthreats.net/2001595

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 11

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (settings)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/settings.php"; http_uri; content:"facebook.com|0d 0a|"; http_header;  reference:url,doc.emergingthreats.net/2010786; classtype:policy-violation; sid:2010786; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_26;)

# 2010786
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (settings)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/settings.php"; http_uri; content:"facebook.com|0d 0a|"; http_header;  reference:url,doc.emergingthreats.net/2010786; classtype:policy-violation; sid:2010786; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_26;)
` 

Name : **Facebook Chat (settings)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010786

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-26

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (send message)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/send.php"; http_uri; content:"facebook.com"; http_header; reference:url,doc.emergingthreats.net/2010784; classtype:policy-violation; sid:2010784; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2010784
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Facebook Chat (send message)"; flow:established,to_server; content:"POST"; http_method; content:"/ajax/chat/send.php"; http_uri; content:"facebook.com"; http_header; reference:url,doc.emergingthreats.net/2010784; classtype:policy-violation; sid:2010784; rev:5; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Facebook Chat (send message)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2010784

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM Client Install"; flow: to_server,established; content:"/ycontent/stats.php?version="; http_uri; nocase; content:"EVENT=InstallBegin"; http_uri; nocase; reference:url,doc.emergingthreats.net/2002659; classtype:policy-violation; sid:2002659; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)

# 2002659
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Yahoo IM Client Install"; flow: to_server,established; content:"/ycontent/stats.php?version="; http_uri; nocase; content:"EVENT=InstallBegin"; http_uri; nocase; reference:url,doc.emergingthreats.net/2002659; classtype:policy-violation; sid:2002659; rev:7; metadata:created_at 2010_07_30, updated_at 2019_09_27;)
` 

Name : **Yahoo IM Client Install** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,doc.emergingthreats.net/2002659

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-09-27

Rev version : 7

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC Channel join"; flow:to_server,established; content:"JOIN |3a 20||23|"; fast_pattern; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101729; rev:11; metadata:created_at 2010_09_23, updated_at 2019_10_07;)

# 2101729
`alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC Channel join"; flow:to_server,established; content:"JOIN |3a 20||23|"; fast_pattern; nocase; flowbits:set,is_proto_irc; classtype:policy-violation; sid:2101729; rev:11; metadata:created_at 2010_09_23, updated_at 2019_10_07;)
` 

Name : **IRC Channel join** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2019-10-07

Rev version : 11

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL CHAT ICQ access"; flow:to_server,established; content:"ICQ"; http_user_agent; depth:3; classtype:policy-violation; sid:2100541; rev:14; metadata:created_at 2010_09_23, updated_at 2020_04_20;)

# 2100541
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL CHAT ICQ access"; flow:to_server,established; content:"ICQ"; http_user_agent; depth:3; classtype:policy-violation; sid:2100541; rev:14; metadata:created_at 2010_09_23, updated_at 2020_04_20;)
` 

Name : **ICQ access** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2020-04-20

Rev version : 14

Category : CHAT

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT General MSN Chat Activity"; flow:established; content:"Content-Type|3A|"; http_header; content:"application/x-msn-messenger"; http_header; reference:url,www.hypothetic.org/docs/msn/general/http_examples.php; reference:url,doc.emergingthreats.net/2009375; classtype:policy-violation; sid:2009375; rev:5; metadata:created_at 2010_07_30, updated_at 2020_04_16;)

# 2009375
`alert http $HOME_NET any <> $EXTERNAL_NET any (msg:"ET CHAT General MSN Chat Activity"; flow:established; content:"Content-Type|3A|"; http_header; content:"application/x-msn-messenger"; http_header; reference:url,www.hypothetic.org/docs/msn/general/http_examples.php; reference:url,doc.emergingthreats.net/2009375; classtype:policy-violation; sid:2009375; rev:5; metadata:created_at 2010_07_30, updated_at 2020_04_16;)
` 

Name : **General MSN Chat Activity** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : policy-violation

URL reference : url,www.hypothetic.org/docs/msn/general/http_examples.php|url,doc.emergingthreats.net/2009375

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2020-04-16

Rev version : 5

Category : CHAT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



